// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/version"
	"gopkg.in/yaml.v3"
)

type Evaluator string

type RuleScope string

const (
	Unscoped               RuleScope = "none"
	DockerScope            RuleScope = "docker"
	KubernetesNodeScope    RuleScope = "kubernetesNode"
	KubernetesClusterScope RuleScope = "kubernetesCluster"
)

type CheckResult string

const (
	// CheckPassed is used to report successful result of a rule check (condition passed)
	CheckPassed CheckResult = "passed"
	// CheckFailed is used to report unsuccessful result of a rule check (condition failed)
	CheckFailed CheckResult = "failed"
	// CheckError is used to report result of a rule check that resulted in an error (unable to evaluate condition)
	CheckError CheckResult = "error"
)

type CheckStatus struct {
	RuleID      string
	Name        string
	Description string
	Version     string
	Framework   string
	Source      string
	InitError   error
	LastEvent   *CheckEvent
}

type CheckEvent struct {
	AgentVersion string                 `json:"agent_version,omitempty"`
	RuleID       string                 `json:"agent_rule_id,omitempty"`
	RuleVersion  int                    `json:"agent_rule_version,omitempty"`
	FrameworkID  string                 `json:"agent_framework_id,omitempty"`
	Evaluator    Evaluator              `json:"evaluator,omitempty"`
	ExpireAt     time.Time              `json:"expire_at,omitempty"`
	Result       CheckResult            `json:"result,omitempty"`
	ResourceType string                 `json:"resource_type,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`
	Tags         []string               `json:"tags"`
	Data         map[string]interface{} `json:"data,omitempty"`

	errReason error `json:"-"`
}

func (e *CheckEvent) String() string {
	s := fmt.Sprintf("%s:%s result=%s", e.FrameworkID, e.RuleID, e.Result)
	if e.ResourceID != "" {
		s += fmt.Sprintf(" resource=%s:%s", e.ResourceType, e.ResourceID)
	}
	if e.Result == CheckError {
		s += fmt.Sprintf(" error=%s", e.errReason)
	} else {
		s += fmt.Sprintf(" data=%v", e.Data)
	}
	return s
}

type Rule struct {
	ID          string       `yaml:"id"`
	Description string       `yaml:"description,omitempty"`
	SkipOnK8s   bool         `yaml:"skipOnKubernetes,omitempty"` // XXX
	Module      string       `yaml:"module,omitempty"`
	Scopes      []RuleScope  `yaml:"scope,omitempty"`
	InputSpecs  []*InputSpec `yaml:"input,omitempty"`
	Imports     []string     `yaml:"imports,omitempty"`
	Period      string       `yaml:"period,omitempty"`
}

func (r *Rule) HasScope(scope RuleScope) bool {
	for _, s := range r.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type Benchmark struct {
	dirname string

	Name        string   `yaml:"name,omitempty"`
	FrameworkID string   `yaml:"framework,omitempty"`
	Version     string   `yaml:"version,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	Rules       []*Rule  `yaml:"rules,omitempty"`
	Source      string   `yaml:"-"`
	Schema      struct {
		Version string `yaml:"version"`
	} `yaml:"schema,omitempty"`
}

func (b *Benchmark) Valid() error {
	if len(b.Rules) == 0 {
		return fmt.Errorf("bad benchmark: empty rule set")
	}
	for _, rule := range b.Rules {
		for _, spec := range rule.InputSpecs {
			if err := spec.Valid(); err != nil {
				return fmt.Errorf("bad benchmark: invalid input spec: %w", err)
			}
		}
	}
	return nil
}

func (b *Benchmark) FilterRules(filter func(*Rule) bool) []*Rule {
	filteredRules := make([]*Rule, 0)
	for _, rule := range b.Rules {
		if filter(rule) {
			filteredRules = append(filteredRules, rule)
		}
	}
	return filteredRules
}

type InputSpec struct {
	File *struct {
		Path   string `yaml:"path" json:"path"`
		Glob   string `yaml:"glob" json:"glob"`
		Parser string `yaml:"parser,omitempty" json:"parser,omitempty"`
	} `yaml:"file,omitempty" json:"file,omitempty"`

	Process *struct {
		Name string   `yaml:"name" json:"name"`
		Envs []string `yaml:"envs,omitempty" json:"envs,omitempty"`
	} `yaml:"process,omitempty" json:"process,omitempty"`

	Group *struct {
		Name string `yaml:"name" json:"name"`
	} `yaml:"group,omitempty" json:"group,omitempty"`

	Audit *struct {
		Path string `yaml:"path" json:"path"`
	} `yaml:"audit,omitempty" json:"audit,omitempty"`

	Docker *struct {
		Kind string `yaml:"kind" json:"kind"`
	} `yaml:"docker,omitempty" json:"docker,omitempty"`

	KubeApiServer *InputSpecKubernetes `yaml:"kubeApiserver,omitempty" json:"kubeApiserver,omitempty"`

	Constants map[string]interface{} `yaml:"constants,omitempty" json:"constants,omitempty"`

	TagName string `yaml:"tag,omitempty" json:"tag,omitempty"`
	Type    string `yaml:"type,omitempty" json:"type,omitempty"`
}

func (i *InputSpec) Valid() error {
	// NOTE(jinroh): the current semantics allow to specify the result type as
	// an "array". It is overly complex and error-prone and shall be removed.
	// Here we enforce that the specified result type is constrained to a
	// specific input type.
	if i.KubeApiServer != nil || i.Docker != nil || i.Audit != nil {
		if i.Type != "array" {
			return fmt.Errorf("input of types kubeApiserver docker and audit have to be arrays")
		}
	} else if i.Type == "array" {
		if i.File == nil {
			return fmt.Errorf("bad input results `array`")
		}
		if isGlob := i.File.Glob != "" || strings.Contains(i.File.Path, "*"); !isGlob {
			return fmt.Errorf("file input results defined as array has to be a glob path")
		}
	}
	return nil
}

type InputSpecKubernetes struct {
	Kind          string `yaml:"kind" json:"kind"`
	Version       string `yaml:"version,omitempty" json:"version,omitempty"`
	Group         string `yaml:"group,omitempty" json:"group,omitempty"`
	Namespace     string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	LabelSelector string `yaml:"labelSelector,omitempty" json:"labelSelector,omitempty"`
	FieldSelector string `yaml:"fieldSelector,omitempty" json:"fieldSelector,omitempty"`
	APIRequest    struct {
		Verb         string `yaml:"verb" json:"verb"`
		ResourceName string `yaml:"resourceName,omitempty" json:"resourceName,omitempty"`
	} `yaml:"apiRequest" json:"apiRequest"`
}

type ResolverOutcome map[string]interface{}

func NewCheckError(evaluator Evaluator, rule *Rule, benchmark *Benchmark, errReason error) *CheckEvent {
	expireAt := time.Now().Add(1 * time.Hour).UTC().Truncate(1 * time.Second)
	return &CheckEvent{
		AgentVersion: version.AgentVersion,
		RuleID:       rule.ID,
		FrameworkID:  benchmark.FrameworkID,
		ExpireAt:     expireAt,
		Evaluator:    evaluator,
		Result:       CheckError,
		Data:         map[string]interface{}{"error": errReason.Error()},

		errReason: errReason,
	}
}

func NewCheckEvent(
	evaluator Evaluator,
	result CheckResult,
	data map[string]interface{},
	resourceID,
	resourceType string,
	rule *Rule,
	benchmark *Benchmark,
) *CheckEvent {
	expireAt := time.Now().Add(1 * time.Hour).UTC().Truncate(1 * time.Second)
	return &CheckEvent{
		AgentVersion: version.AgentVersion,
		RuleID:       rule.ID,
		FrameworkID:  benchmark.FrameworkID,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		ExpireAt:     expireAt,
		Evaluator:    evaluator,
		Result:       result,
		Data:         data,
	}
}

func LoadBenchmarkFiles(rootDir string, filenames ...string) ([]*Benchmark, error) {
	benchmarks := make([]*Benchmark, 0)
	for _, filename := range filenames {
		b, err := loadFile(rootDir, filename)
		if err != nil {
			return nil, err
		}
		var benchmark Benchmark
		if err := yaml.Unmarshal(b, &benchmark); err != nil {
			return nil, err
		}
		benchmark.dirname = rootDir
		if err := benchmark.Valid(); err != nil {
			return nil, err
		}
		benchmarks = append(benchmarks, &benchmark)
	}
	return benchmarks, nil
}

func ListBenchmarksFiles(rootDir string) []string {
	pattern := filepath.Join(rootDir, "/*.yaml")
	benchmarks, _ := filepath.Glob(pattern) // Only possible error is a ErrBadPatter which we ignore.
	for i, path := range benchmarks {
		benchmarks[i] = filepath.Base(path)
	}
	sort.Strings(benchmarks)
	return benchmarks
}

func loadFile(rootDir, filename string) ([]byte, error) {
	path := filepath.Join(rootDir, filepath.Join("/", filename))
	return os.ReadFile(path)
}

type BenchmarkPusher struct {
	ch     chan *Benchmark
	load   func() ([]*Benchmark, error)
	ticker *time.Ticker
}

func NewBenchmarkPusher(ctx context.Context, d time.Duration, load func() ([]*Benchmark, error)) *BenchmarkPusher {
	ticker := time.NewTicker(d)
	bp := &BenchmarkPusher{
		ch:     make(chan *Benchmark),
		load:   load,
		ticker: ticker,
	}
	go bp.run(ctx)
	return bp
}

func (bp *BenchmarkPusher) run(ctx context.Context) {
	defer bp.ticker.Stop()
	var benchmarks []*Benchmark
	index := 0
	for {
		if index == 0 {
			bs, err := bp.load()
			if err != nil {
				benchmarks = nil
				log.Warnf("could not load benchmarks: %v", err)
			} else {
				benchmarks = bs
			}
		}
		if len(benchmarks) == 0 {
			log.Infof("no benchmarks to run")
		} else {
			benchmark := benchmarks[index]
			log.Tracef("pushing benchmark %s", benchmark.FrameworkID)
			bp.ch <- benchmark
		}
		select {
		case <-bp.ticker.C:
		case <-ctx.Done():
			return
		}
		index = (index + 1) % len(benchmarks)
	}
}

func (bp *BenchmarkPusher) Next() <-chan *Benchmark {
	return bp.ch
}
