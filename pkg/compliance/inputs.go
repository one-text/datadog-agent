// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/compliance/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/jsonquery"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/version"
	"github.com/DataDog/datadog-go/v5/statsd"
	dockertypes "github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/elastic/go-libaudit/rule"
	auditrule "github.com/elastic/go-libaudit/rule"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/shirou/gopsutil/v3/process"
	yamlv2 "gopkg.in/yaml.v2"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// NOTE(jinroh): the way inputs are defined, loaded and summarized could be
// simplified. We'll probably revisit the semantics but for this first
// implementation we wanted to be 100% retro-compatible.

const defaultTimeout = 10 * time.Second

var errIsDir = errors.New("is directory")

// TODO(jinroh): deprecate this process.flag builtin kept for
// retro-compatibility
var processFlagBuiltinReg = regexp.MustCompile(`process\.flag\("(\S+)", "(\S+)"\)`)

var ErrIncompatibleEnvironment = errors.New("environment not compatible this type of input")

type DockerProvider func(context.Context) (docker.CommonAPIClient, error)
type KubernetesProvider func(context.Context) (dynamic.Interface, error)
type LinuxAuditProvider func(context.Context) (LinuxAuditClient, error)

type LinuxAuditClient interface {
	GetFileWatchRules() ([]*rule.FileWatchRule, error)
	Close() error
}

func DefaultDockerProvider(ctx context.Context) (docker.CommonAPIClient, error) {
	return newDockerClient(ctx)
}

func DefaultLinuxAuditProvider(ctx context.Context) (LinuxAuditClient, error) {
	return newLinuxAuditClient()
}

type fileCache struct {
	path  string
	data  []byte
	perms uint64
	user  string
	group string
}

type Resolver interface {
	ResolveInputs(ctx context.Context, rule *Rule) (ResolverOutcome, error)
	Close() error
}

type defaultResolver struct {
	opts ResolverOptions

	procsCache []*process.Process
	filesCache []fileCache
	lruCache   *simplelru.LRU[string, interface{}]

	dockerCl     docker.CommonAPIClient
	kubernetesCl dynamic.Interface
	linuxAuditCl LinuxAuditClient
}

type ResolverOptions struct {
	Hostname     string
	HostRoot     string
	StatsdClient statsd.ClientInterface

	DockerProvider
	KubernetesProvider
	LinuxAuditProvider
}

func NewResolver(opts ResolverOptions) Resolver {
	lruCache, _ := simplelru.NewLRU[string, interface{}](32, nil)
	return &defaultResolver{
		opts:     opts,
		lruCache: lruCache,
	}
}

func (r *defaultResolver) Close() error {
	var errc error
	if r.dockerCl != nil {
		r.dockerCl.Close()
		r.dockerCl = nil
	}
	if r.linuxAuditCl != nil {
		r.linuxAuditCl.Close()
		r.linuxAuditCl = nil
	}
	r.kubernetesCl = nil
	r.lruCache.Purge()
	r.procsCache = nil
	r.filesCache = nil
	return errc
}

func (r *defaultResolver) ResolveInputs(ctx context.Context, rule *Rule) (ResolverOutcome, error) {
	context := struct {
		RuleID            string                `json:"ruleID"`
		Hostname          string                `json:"hostname"`
		KubernetesCluster string                `json:"kubernetes_cluster,omitempty"`
		InputSpecs        map[string]*InputSpec `json:"input"`
	}{
		RuleID:     rule.ID,
		Hostname:   r.opts.Hostname,
		InputSpecs: make(map[string]*InputSpec),
	}

	resolved := make(map[string]interface{})

	if rule.HasScope(DockerScope) {
		if r.opts.DockerProvider == nil {
			return nil, ErrIncompatibleEnvironment
		}
	}

	if rule.HasScope(KubernetesClusterScope) || rule.HasScope(KubernetesNodeScope) {
		if r.opts.KubernetesProvider == nil {
			return nil, ErrIncompatibleEnvironment
		}
	}

	for _, spec := range rule.InputSpecs {
		start := time.Now()

		var err error
		var resultType string
		var result interface{}
		var kubernetesCluster string

		switch {
		case spec.File != nil:
			resultType = "file"
			path := strings.TrimSpace(spec.File.Path)
			if matches := processFlagBuiltinReg.FindStringSubmatch(path); len(matches) == 3 {
				processName, processFlag := matches[1], matches[2]
				result, err = r.resolveFileFromProcessFlag(ctx, processName, processFlag, spec.File.Parser)
			} else if spec.File.Glob != "" && path == "" {
				result, err = r.resolveFileGlob(ctx, spec.File.Glob, spec.File.Parser)
			} else if strings.Contains(path, "*") {
				result, err = r.resolveFileGlob(ctx, path, spec.File.Parser)
			} else {
				result, err = r.resolveFilePath(ctx, "", path, spec.File.Parser)
			}
			if errors.Is(err, os.ErrPermission) ||
				errors.Is(err, os.ErrNotExist) ||
				errors.Is(err, os.ErrClosed) ||
				errors.Is(err, errIsDir) {
				result, err = nil, nil
			}

		case spec.Process != nil:
			resultType = "process"
			result, err = r.resolveProcess(ctx, spec.Process.Name, spec.Process.Envs)

		case spec.Group != nil:
			resultType = "group"
			result, err = r.resolveGroup(ctx, spec.Group.Name)

		case spec.Audit != nil:
			resultType = "audit"
			result, err = r.resolveAudit(ctx, spec.Audit.Path)

		case spec.Docker != nil:
			resultType = "docker"
			result, err = r.resolveDocker(ctx, spec.Docker.Kind)

		case spec.KubeApiServer != nil:
			resultType = "kubernetes"
			result, err = r.resolveKubeApiserver(ctx, spec.KubeApiServer)
			if clusterID, err := r.resolveKubeClusterID(ctx); err == nil {
				kubernetesCluster = clusterID
			}

		case spec.Constants != nil:
			resultType = "constants"
			result = spec.Constants

		default:
			return nil, fmt.Errorf("bad input spec")
		}
		tagName := resultType
		if spec.TagName != "" {
			tagName = spec.TagName
		}
		if err != nil {
			return nil, fmt.Errorf("could not resolve input spec %s(tagged=%q): %w", resultType, tagName, err)
		}
		if _, ok := resolved[tagName]; ok {
			return nil, fmt.Errorf("input with tag %q already set", tagName)
		}
		if _, ok := context.InputSpecs[tagName]; ok {
			return nil, fmt.Errorf("input with tag %q already set", tagName)
		}

		context.InputSpecs[tagName] = spec
		if kubernetesCluster != "" {
			context.KubernetesCluster = kubernetesCluster
		}
		if r, ok := result.([]interface{}); ok && reflect.ValueOf(r).IsNil() {
			result = nil
		}
		if result != nil {
			resolved[tagName] = result
		}

		if statsdClient := r.opts.StatsdClient; statsdClient != nil && resultType != "constants" {
			tags := []string{
				"rule_id:" + rule.ID,
				"rule_input_type:" + resultType,
				"agent_version:" + version.AgentVersion,
			}
			if err := statsdClient.Count(metrics.MetricInputsHits, 1, tags, 1.0); err != nil {
				log.Errorf("failed to send input metric: %v", err)
			}
			if err := statsdClient.Timing(metrics.MetricInputsDuration, time.Since(start), tags, 1.0); err != nil {
				log.Errorf("failed to send input metric: %v", err)
			}
		}
	}

	preMarshal := make(map[string]interface{})
	for k, v := range resolved {
		preMarshal[k] = v
	}
	if _, ok := preMarshal["context"]; ok {
		return nil, fmt.Errorf("\"context\" key is reserved")
	}
	preMarshal["context"] = context
	preMarshalBuf, err := json.Marshal(preMarshal)
	if err != nil {
		return nil, fmt.Errorf("could not marshal resolver outcome: %w", err)
	}

	var outcome ResolverOutcome
	log.Tracef("rego input for rule=%s:\n%s", rule.ID, preMarshalBuf)
	if err := json.Unmarshal(preMarshalBuf, &outcome); err != nil {
		return nil, fmt.Errorf("could not unmarshal resolver outcome: %w", err)
	}

	if statsdClient := r.opts.StatsdClient; statsdClient != nil {
		tags := []string{"rule_id:" + rule.ID, "agent_version:" + version.AgentVersion}
		if err := statsdClient.Gauge(metrics.MetricInputsSize, float64(len(preMarshalBuf)), tags, 1.0); err != nil {
			log.Errorf("failed to send input size metric: %v", err)
		}
	}

	return outcome, nil
}

func (r *defaultResolver) pathNormalizeToHostRoot(path string) string {
	if r.opts.HostRoot != "" {
		return filepath.Join(r.opts.HostRoot, path)
	}
	return path
}

func (r *defaultResolver) pathRelativeToHostRoot(path string) string {
	if r.opts.HostRoot != "" {
		p, err := filepath.Rel(r.opts.HostRoot, path)
		if err != nil {
			return path
		}
		return string(os.PathSeparator) + p
	}
	return path
}

func (r *defaultResolver) getFileMetaCache(path string) (*fileCache, bool) {
	for _, f := range r.filesCache {
		if f.path == path {
			return &f, true
		}
	}
	return nil, false
}

func (r *defaultResolver) addFileMetaCache(meta *fileCache) {
	const maxFilesCached = 16
	r.filesCache = append(r.filesCache, *meta)
	if len(r.filesCache) > maxFilesCached {
		r.filesCache = r.filesCache[1:]
	}
}

func (r *defaultResolver) resolveFilePath(ctx context.Context, glob, path, parser string) (interface{}, error) {
	path = r.pathNormalizeToHostRoot(path)
	meta, ok := r.getFileMetaCache(path)
	if !ok {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			return nil, errIsDir
		}
		perms := uint64(info.Mode() & os.ModePerm)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		meta = &fileCache{
			path:  path,
			data:  data,
			perms: perms,
			user:  getFileUser(info),
			group: getFileGroup(info),
		}
		r.addFileMetaCache(meta)
	}

	var content interface{}
	var err error
	switch parser {
	case "yaml":
		err = yaml.Unmarshal(meta.data, &content)
		if err != nil {
			err = yamlv2.Unmarshal(meta.data, &content)
		}
		if err == nil {
			content = jsonquery.NormalizeYAMLForGoJQ(content)
		}
	case "json":
		err = json.Unmarshal(meta.data, &content)
	case "raw":
		content = string(meta.data)
	default:
		content = ""
	}
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"path":        r.pathRelativeToHostRoot(path),
		"glob":        glob,
		"permissions": meta.perms,
		"user":        meta.user,
		"group":       meta.group,
		"content":     content,
	}, nil
}

func (r *defaultResolver) resolveFileFromProcessFlag(ctx context.Context, name, flag, parser string) (interface{}, error) {
	procs, err := r.getProcs(ctx)
	if err != nil {
		return nil, err
	}
	var proc *process.Process
	for _, p := range procs {
		n, _ := p.Name()
		if n == name {
			proc = p
			break
		}
	}
	if proc == nil {
		return nil, fmt.Errorf("could not find process %q for file content", name)
	}

	cmdlineSlice, err := proc.CmdlineSlice()
	if err != nil {
		return nil, fmt.Errorf("could not get cmdline value for process %q: %w", name, err)
	}

	flags := parseCmdLineFlags(cmdlineSlice)
	path, ok := flags[flag]
	if !ok {
		return nil, fmt.Errorf("process %q has no flag %q", name, flag)
	}
	return r.resolveFilePath(ctx, "", path, parser)
}

func (r *defaultResolver) resolveFileGlob(ctx context.Context, glob, parser string) (interface{}, error) {
	paths, _ := filepath.Glob(glob) // We ignore errors from Glob which are never I/O errors
	var resolved []interface{}
	for _, path := range paths {
		file, err := r.resolveFilePath(ctx, glob, path, parser)
		if err != nil {
			continue
		}
		resolved = append(resolved, file)
	}
	return resolved, nil
}

func (r *defaultResolver) resolveProcess(ctx context.Context, name string, filteredEnvs []string) (interface{}, error) {
	procs, err := r.getProcs(ctx)
	if err != nil {
		return nil, err
	}
	var resolved []interface{}
	for _, p := range procs {
		n, _ := p.Name()
		if n != name {
			continue
		}
		cmdLine, err := p.CmdlineSlice()
		if err != nil {
			return nil, err
		}
		envs, err := p.Environ()
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, map[string]interface{}{
			"name":    name,
			"pid":     p.Pid,
			"exe":     "",
			"cmdLine": cmdLine,
			"flags":   parseCmdLineFlags(cmdLine),
			"envs":    parseEnvironMap(envs, filteredEnvs),
		})
	}
	return resolved, nil
}

func (r *defaultResolver) getProcs(ctx context.Context) ([]*process.Process, error) {
	if r.procsCache == nil {
		procs, err := process.ProcessesWithContext(ctx)
		if err != nil {
			return nil, err
		}
		r.procsCache = procs
	}
	return r.procsCache, nil
}

func (r *defaultResolver) resolveGroup(ctx context.Context, name string) (interface{}, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	prefix := name + ":"
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		parts := strings.SplitN(string(line), ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("malformed group file format")
		}
		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to parse group ID for %s: %w", name, err)
		}
		users := strings.Split(parts[3], ",")
		return map[string]interface{}{
			"name":  name,
			"users": users,
			"id":    gid,
		}, nil
	}
	return nil, nil
}

func (r *defaultResolver) resolveAudit(ctx context.Context, path string) (interface{}, error) {
	key := "linuxaudit:" + path
	if v, ok := r.lruCache.Get(key); ok {
		return v, nil
	}

	cl, err := r.getLinuxAuditCl(ctx)
	if cl == nil {
		return nil, err
	}

	rules, err := cl.GetFileWatchRules()
	if err != nil {
		return nil, err
	}
	var resolved []interface{}
	for _, rule := range rules {
		if rule.Path == path {
			permissions := ""
			for _, p := range rule.Permissions {
				switch p {
				case auditrule.ReadAccessType:
					permissions += "r"
				case auditrule.WriteAccessType:
					permissions += "w"
				case auditrule.ExecuteAccessType:
					permissions += "e"
				case auditrule.AttributeChangeAccessType:
					permissions += "a"
				}
			}
			resolved = append(resolved, map[string]interface{}{
				"path":        path,
				"enabled":     true,
				"permissions": permissions,
			})
		}
	}

	r.lruCache.Add(key, resolved)
	return resolved, nil
}

func (r *defaultResolver) resolveDocker(ctx context.Context, kind string) (interface{}, error) {
	key := "docker:" + kind
	if v, ok := r.lruCache.Get(key); ok {
		return v, nil
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	cl, err := r.getDockerCl(ctx)
	if err != nil {
		return nil, err
	}

	var resolved []interface{}
	switch kind {
	case "image":
		list, err := cl.ImageList(ctx, dockertypes.ImageListOptions{All: true})
		if err != nil {
			return nil, err
		}
		for _, im := range list {
			image, _, err := cl.ImageInspectWithRaw(ctx, im.ID)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, map[string]interface{}{
				"id":      image.ID,
				"tags":    image.RepoTags,
				"inspect": image,
			})
		}
	case "container":
		list, err := cl.ContainerList(ctx, dockertypes.ContainerListOptions{All: true})
		if err != nil {
			return nil, err
		}
		for _, cn := range list {
			container, _, err := cl.ContainerInspectWithRaw(ctx, cn.ID, false)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, map[string]interface{}{
				"id":      container.ID,
				"name":    container.Name,
				"image":   container.Image,
				"inspect": container,
			})
		}
	case "network":
		networks, err := cl.NetworkList(ctx, dockertypes.NetworkListOptions{})
		if err != nil {
			return nil, err
		}
		for _, nw := range networks {
			resolved = append(resolved, map[string]interface{}{
				"id":      nw.ID,
				"name":    nw.Name,
				"inspect": nw,
			})
		}
	case "info":
		info, err := cl.Info(ctx)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, map[string]interface{}{
			"inspect": info,
		})
	case "version":
		version, err := cl.ServerVersion(ctx)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, map[string]interface{}{
			"version":       version.Version,
			"apiVersion":    version.APIVersion,
			"platform":      version.Platform.Name,
			"experimental":  version.Experimental,
			"os":            version.Os,
			"arch":          version.Arch,
			"kernelVersion": version.KernelVersion,
		})
	default:
		return nil, fmt.Errorf("unsupported docker object kind '%q'", kind)
	}

	r.lruCache.Add(key, resolved)
	return resolved, nil
}

func (r *defaultResolver) resolveKubeClusterID(ctx context.Context) (string, error) {
	key := "kubeclusterid"
	if v, ok := r.lruCache.Get(key); ok {
		return v.(string), nil
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	cl, err := r.getKubernetesCl(ctx)
	if err != nil {
		return "", err
	}

	resourceDef := cl.Resource(schema.GroupVersionResource{
		Resource: "namespaces",
		Version:  "v1",
	})
	resource, err := resourceDef.Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	clusterID := string(resource.GetUID())
	r.lruCache.Add(key, clusterID)
	return clusterID, nil
}

func (r *defaultResolver) resolveKubeApiserver(ctx context.Context, opts *InputSpecKubernetes) (interface{}, error) {
	// TODO(jinroh): minimal caching ?
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	cl, err := r.getKubernetesCl(ctx)
	if err != nil {
		return nil, err
	}

	if len(opts.Kind) == 0 {
		return nil, fmt.Errorf("cannot run Kubeapiserver check, resource kind is empty")
	}

	if len(opts.APIRequest.Verb) == 0 {
		return nil, fmt.Errorf("cannot run Kubeapiserver check, action verb is empty")
	}

	if len(opts.Version) == 0 {
		opts.Version = "v1"
	}

	resourceSchema := schema.GroupVersionResource{
		Group:    opts.Group,
		Resource: opts.Kind,
		Version:  opts.Version,
	}

	resourceDef := cl.Resource(resourceSchema)
	var resourceAPI dynamic.ResourceInterface
	if len(opts.Namespace) > 0 {
		resourceAPI = resourceDef.Namespace(opts.Namespace)
	} else {
		resourceAPI = resourceDef
	}

	var items []unstructured.Unstructured
	api := opts.APIRequest
	switch api.Verb {
	case "get":
		if len(api.ResourceName) == 0 {
			return nil, fmt.Errorf("unable to use 'get' apirequest without resource name")
		}
		resource, err := resourceAPI.Get(ctx, opts.APIRequest.ResourceName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("unable to get Kube resource:'%v', ns:'%s' name:'%s', err: %v",
				resourceSchema, opts.Namespace, api.ResourceName, err)
		}
		items = []unstructured.Unstructured{*resource}
	case "list":
		list, err := resourceAPI.List(ctx, metav1.ListOptions{
			LabelSelector: opts.LabelSelector,
			FieldSelector: opts.FieldSelector,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to list Kube resources:'%v', ns:'%s' name:'%s', err: %v",
				resourceSchema, opts.Namespace, api.ResourceName, err)
		}
		items = list.Items
	}

	resolved := make([]interface{}, 0, len(items))
	for _, resource := range items {
		resolved = append(resolved, map[string]interface{}{
			"kind":      resource.GetObjectKind().GroupVersionKind().Kind,
			"group":     resource.GetObjectKind().GroupVersionKind().Group,
			"version":   resource.GetObjectKind().GroupVersionKind().Version,
			"namespace": resource.GetNamespace(),
			"name":      resource.GetName(),
			"resource":  resource,
		})
	}
	return resolved, nil
}

func (r *defaultResolver) getDockerCl(ctx context.Context) (docker.CommonAPIClient, error) {
	if r.opts.DockerProvider == nil {
		return nil, ErrIncompatibleEnvironment
	}
	if r.dockerCl == nil {
		cl, err := r.opts.DockerProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("docker client is not configured: %w", err)
		}
		r.dockerCl = cl
	}
	if r.dockerCl == nil {
		return nil, fmt.Errorf("docker client is not configured")
	}
	return r.dockerCl, nil
}

func (r *defaultResolver) getKubernetesCl(ctx context.Context) (dynamic.Interface, error) {
	if r.opts.KubernetesProvider == nil {
		return nil, ErrIncompatibleEnvironment
	}
	if r.kubernetesCl == nil {
		cl, err := r.opts.KubernetesProvider(ctx)
		if err != nil {
			return nil, fmt.Errorf("kubernetes client is not configured: %w", err)
		}
		r.kubernetesCl = cl
	}
	if r.kubernetesCl == nil {
		return nil, fmt.Errorf("kubernetes client is not configured")
	}
	return r.kubernetesCl, nil
}

func (r *defaultResolver) getLinuxAuditCl(ctx context.Context) (LinuxAuditClient, error) {
	if r.opts.LinuxAuditProvider == nil {
		return nil, ErrIncompatibleEnvironment
	}
	if r.linuxAuditCl == nil {
		cl, err := r.opts.LinuxAuditProvider(ctx)
		if err != nil {
			return nil, err
		}
		r.linuxAuditCl = cl
	}
	return r.linuxAuditCl, nil
}

func parseCmdLineFlags(cmdline []string) map[string]string {
	flagsMap := make(map[string]string, 0)
	pendingFlagValue := false
	for i, arg := range cmdline {
		if strings.HasPrefix(arg, "-") {
			parts := strings.SplitN(arg, "=", 2)
			// We have -xxx=yyy, considering the flag completely resolved
			if len(parts) == 2 {
				flagsMap[parts[0]] = parts[1]
			} else {
				flagsMap[parts[0]] = ""
				pendingFlagValue = true
			}
		} else {
			if pendingFlagValue {
				flagsMap[cmdline[i-1]] = arg
			} else {
				flagsMap[arg] = ""
			}
		}
	}
	return flagsMap
}

func parseEnvironMap(envs, filteredEnvs []string) map[string]string {
	envsMap := make(map[string]string, len(filteredEnvs))
	if len(filteredEnvs) == 0 {
		return envsMap
	}
	for _, envValue := range envs {
		for _, envName := range filteredEnvs {
			prefix := envName + "="
			if strings.HasPrefix(envValue, prefix) {
				envsMap[envName] = strings.TrimPrefix(envValue, prefix)
			} else if envValue == envName {
				envsMap[envName] = ""
			}
		}
	}
	return envsMap
}
