package compliance

import (
	"time"

	coreconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/logs/auditor"
	"github.com/DataDog/datadog-agent/pkg/logs/client"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/diagnostic"
	"github.com/DataDog/datadog-agent/pkg/logs/message"
	"github.com/DataDog/datadog-agent/pkg/logs/pipeline"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/security/common"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/util/startstop"
)

type reporter struct {
	logSource *sources.LogSource
	logChan   chan *message.Message
}

// NewLogReporter instantiates a new log reporter
func NewLogReporter(stopper startstop.Stopper, sourceName, sourceType, runPath string, endpoints *config.Endpoints, context *client.DestinationsContext) (common.RawReporter, error) {
	health := health.RegisterLiveness(sourceType)

	// setup the auditor
	auditor := auditor.New(runPath, sourceType+"-registry.json", coreconfig.DefaultAuditorTTL, health)
	auditor.Start()

	// setup the pipeline provider that provides pairs of processor and sender
	pipelineProvider := pipeline.NewProvider(config.NumberOfPipelines, auditor, &diagnostic.NoopMessageReceiver{}, nil, endpoints, context)
	pipelineProvider.Start()

	stopper.Add(pipelineProvider)
	stopper.Add(auditor)

	logSource := sources.NewLogSource(
		sourceName,
		&config.LogsConfig{
			Type:    sourceType,
			Service: sourceName,
			Source:  sourceName,
		},
	)
	logChan := pipelineProvider.NextPipelineChan()

	return &reporter{
		logSource: logSource,
		logChan:   logChan,
	}, nil
}

func (r *reporter) ReportRaw(content []byte, service string, tags ...string) {
	origin := message.NewOrigin(r.logSource)
	origin.SetTags(tags)
	origin.SetService(service)
	msg := message.NewMessage(content, origin, message.StatusInfo, time.Now().UnixNano())
	r.logChan <- msg
}
