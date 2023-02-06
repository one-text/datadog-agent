// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/compliance/metrics"
	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/security/common"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-go/v5/statsd"
)

const containersCountMetricName = "datadog.security_agent.compliance.containers_running"

var status = expvar.NewMap("compliance")

type AgentOptions struct {
	ResolverOptions
	ConfigDir        string
	Reporter         common.RawReporter
	Endpoints        *config.Endpoints
	BenchmarkVisitor BenchmarkVisitor
	RunInterval      time.Duration
	EvalThrottling   time.Duration
}

type BenchmarkVisitor func(*Benchmark) *Benchmark

type Agent struct {
	opts AgentOptions

	telemetry     *common.ContainersTelemetry
	checksMonitor *ChecksMonitor

	finish chan struct{}
	cancel context.CancelFunc
}

func NewAgent(opts AgentOptions) *Agent {
	if opts.ConfigDir == "" {
		panic("compliance: missing agent configuration directory")
	}
	if opts.Endpoints == nil {
		panic("compliance: missing agent endpoints")
	}
	if opts.Reporter == nil {
		panic("compliance: missing agent reporter")
	}
	if opts.RunInterval == 0 {
		opts.RunInterval = 20 * time.Minute
	}
	if opts.EvalThrottling == 0 {
		opts.EvalThrottling = 500 * time.Millisecond
	}
	if opts.BenchmarkVisitor == nil {
		opts.BenchmarkVisitor = func(b *Benchmark) *Benchmark { return b }
	}
	return &Agent{
		opts: opts,
	}
}

func (a *Agent) Start() error {
	telemetry, err := common.NewContainersTelemetry()
	if err != nil {
		log.Errorf("could not start containers telemetry: %v", err)
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.checksMonitor = NewChecksMonitor(a.opts.StatsdClient)
	a.telemetry = telemetry
	a.cancel = cancel
	a.finish = make(chan struct{})

	status.Set(
		"Checks",
		expvar.Func(func() interface{} {
			return a.checksMonitor.GetChecksStatus()
		}),
	)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		a.runTelemetry(ctx)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		a.runRegoBenchmarks(ctx)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		a.runOscapBenchmarks(ctx)
		wg.Done()
	}()

	go func() {
		<-ctx.Done()
		wg.Wait()
		close(a.finish)
	}()

	return nil
}

func (a *Agent) Stop() {
	log.Tracef("shutting down compliance agent")
	a.cancel()
	select {
	case <-time.After(10 * time.Second):
	case <-a.finish:
	}
	log.Infof("compliance agent shut down")
}

func (a *Agent) loadBenchmarks() ([]*Benchmark, error) {
	benchmarks, err := LoadBenchmarkFiles(a.opts.ConfigDir, ListBenchmarksFiles(a.opts.ConfigDir)...)
	if err != nil {
		return nil, err
	}
	var filteredBenchmarks []*Benchmark
	for _, b := range benchmarks {
		if benchmark := a.opts.BenchmarkVisitor(b); benchmark != nil {
			filteredBenchmarks = append(filteredBenchmarks, benchmark)
		}
	}
	a.checksMonitor.AddBenchmarks(filteredBenchmarks...)
	return filteredBenchmarks, nil
}

func (a *Agent) runRegoBenchmarks(ctx context.Context) {
	throttler := time.NewTicker(a.opts.EvalThrottling)
	defer throttler.Stop()

	benchmarksPusher := NewBenchmarkPusher(ctx, a.opts.RunInterval, a.loadBenchmarks)
	for benchmark := range benchmarksPusher.Next() {
		stream := make(chan *CheckEvent)
		go func() {
			resolver := NewResolver(a.opts.ResolverOptions)
			defer resolver.Close()
			runner := NewRegoBenchmarkRunner(resolver, benchmark)
			runner.RunBenchmark(ctx, stream)
			close(stream)
		}()

		for event := range stream {
			a.checksMonitor.Update(event)
			buf, err := json.Marshal(event)
			if err != nil {
				log.Errorf("failed to serialize event from benchmark=%s rule=%s: %v", benchmark.FrameworkID, event.RuleID, err)
			} else {
				log.Tracef("received event from benchmark=%s rule=%s: %s", benchmark.FrameworkID, event.RuleID, buf)
				a.opts.Reporter.ReportRaw(buf, "")
			}
			select {
			case <-ctx.Done():
				return
			case <-throttler.C:
			}
		}
	}
}

func (a *Agent) runOscapBenchmarks(ctx context.Context) {
	<-ctx.Done()
}

func (a *Agent) runTelemetry(ctx context.Context) {
	log.Info("Start collecting Compliance telemetry")
	defer log.Info("Stopping Compliance telemetry")

	metricsTicker := time.NewTicker(1 * time.Minute)
	defer metricsTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-metricsTicker.C:
			a.telemetry.ReportContainers(containersCountMetricName)
		}
	}
}

func (a *Agent) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"endpoints": a.opts.Endpoints.GetStatus(),
	}
}

type ChecksMonitor struct {
	statsdClient statsd.ClientInterface
	statuses     map[string]*CheckStatus
	mu           sync.RWMutex
}

func NewChecksMonitor(statsdClient statsd.ClientInterface) *ChecksMonitor {
	return &ChecksMonitor{
		statuses:     make(map[string]*CheckStatus),
		statsdClient: statsdClient,
	}
}

func (m *ChecksMonitor) GetChecksStatus() interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	statuses := make([]*CheckStatus, 0, len(m.statuses))
	for _, status := range m.statuses {
		statuses = append(statuses, status)
	}
	return statuses
}

func (m *ChecksMonitor) AddBenchmarks(benchmarks ...*Benchmark) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, benchmark := range benchmarks {
		for _, rule := range benchmark.Rules {
			m.statuses[rule.ID] = &CheckStatus{
				RuleID:      rule.ID,
				Description: rule.Description,
				Name:        fmt.Sprintf("%s: %s", rule.ID, rule.Description),
				Framework:   benchmark.FrameworkID,
				Source:      benchmark.Source,
				Version:     benchmark.Version,
				InitError:   nil,
			}
		}
	}
}

func (m *ChecksMonitor) Update(event *CheckEvent) {
	if client := m.statsdClient; client != nil {
		tags := []string{
			"rule_id:" + event.RuleID,
			"rule_result:" + string(event.Result),
			"agent_version:" + event.AgentVersion,
		}
		if err := client.Gauge(metrics.MetricChecksStatuses, 1, tags, 1.0); err != nil {
			log.Errorf("failed to send checks metric: %v", err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	status, ok := m.statuses[event.RuleID]
	if !ok || status == nil {
		log.Errorf("check for rule=%s was not registered in checks monitor statuses", event.RuleID)
	} else {
		status.LastEvent = event
	}
}
