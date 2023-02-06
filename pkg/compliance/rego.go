// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/DataDog/datadog-agent/pkg/compliance/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	regoast "github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	regotypes "github.com/open-policy-agent/opa/types"
)

const RegoEvaluator Evaluator = "rego"

type RegoRunner struct {
	benchmark *Benchmark
	resolver  Resolver
}

func NewRegoBenchmarkRunner(resolver Resolver, benchmark *Benchmark) *RegoRunner {
	return &RegoRunner{
		benchmark: benchmark,
		resolver:  resolver,
	}
}

func (rr *RegoRunner) sendEvents(ctx context.Context, stream chan<- *CheckEvent, events ...*CheckEvent) {
	for _, event := range events {
		select {
		case stream <- event:
			log.Tracef("sent event %s", event)
		case <-ctx.Done():
		}
	}
}

func (rr *RegoRunner) RunBenchmark(ctx context.Context, stream chan<- *CheckEvent) {
	for _, rule := range rr.benchmark.Rules {
		if len(rule.InputSpecs) == 0 {
			continue
		}

		resolverOutcome, err := rr.resolver.ResolveInputs(ctx, rule)
		if errors.Is(err, ErrIncompatibleEnvironment) {
			continue
		}
		if err != nil {
			errReason := fmt.Errorf("input resolution error for rule=%s: %w", rule.ID, err)
			rr.sendEvents(ctx, stream, NewCheckError(RegoEvaluator, rule, rr.benchmark, errReason))
			continue
		}

		log.Infof("running rego check for rule=%s", rule.ID)
		events, err := rr.runRegoEvaluation(ctx, rule, resolverOutcome)
		if err != nil {
			errReason := fmt.Errorf("rego rule evaluation error for rule=%s: %w", rule.ID, err)
			rr.sendEvents(ctx, stream, NewCheckError(RegoEvaluator, rule, rr.benchmark, errReason))
			continue
		}

		rr.sendEvents(ctx, stream, events...)
	}
}

func (rr *RegoRunner) RunBenchmarkGatherEvents(ctx context.Context) []*CheckEvent {
	stream := make(chan *CheckEvent)
	go func() {
		rr.RunBenchmark(ctx, stream)
		close(stream)
	}()
	var events []*CheckEvent
	for event := range stream {
		events = append(events, event)
	}
	return events
}

func (rr *RegoRunner) runRegoEvaluation(ctx context.Context, rule *Rule, resolverOutcome ResolverOutcome) ([]*CheckEvent, error) {
	log.Tracef("building rego modules for rule=%s", rule.ID)
	modules, err := buildRegoModules(rr.benchmark.dirname, rule)
	if err != nil {
		return nil, fmt.Errorf("could not build rego modules: %w", err)
	}

	var options []func(*rego.Rego)
	for name, source := range modules {
		options = append(options, rego.Module(name, source))
	}
	options = append(options, regoBuiltins...)
	options = append(options,
		rego.Query("data.datadog.findings"),
		rego.Metrics(metrics.NewRegoTelemetry()),
		rego.Input(resolverOutcome),
	)

	log.Tracef("starting rego evaluation for rule=%s:%s", rr.benchmark.FrameworkID, rule.ID)
	r := rego.New(options...)
	rSet, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("rego eval: %w", err)
	}
	if len(rSet) == 0 || len(rSet[0].Expressions) == 0 {
		return nil, fmt.Errorf("empty results set")
	}

	results, ok := rSet[0].Expressions[0].Value.([]interface{})
	if !ok {
		return nil, fmt.Errorf("could not cast expression value")
	}

	log.TraceFunc(func() string {
		b, _ := json.MarshalIndent(results, "", "\t")
		return fmt.Sprintf("rego evaluation results for %s:%s:\n%s",
			rr.benchmark.FrameworkID, rule.ID, b)
	})

	events := make([]*CheckEvent, 0, len(results))
	for _, data := range results {
		events = append(events, newCheckEventFromRegoResult(data, rule, resolverOutcome, rr.benchmark))
	}
	return events, nil
}

func newCheckEventFromRegoResult(data interface{}, rule *Rule, resolverOutcome ResolverOutcome, benchmark *Benchmark) *CheckEvent {
	m, ok := data.(map[string]interface{})
	if !ok || m == nil {
		return NewCheckError(RegoEvaluator, rule, benchmark, fmt.Errorf("failed to cast event"))
	}
	var result CheckResult
	var errReason error
	status, _ := m["status"].(string)
	switch status {
	case "passed", "pass":
		result = CheckPassed
	case "failing", "fail":
		result = CheckFailed
	case "err", "error":
		d, _ := m["data"].(map[string]interface{})
		errMsg, _ := d["error"].(string)
		if errMsg == "" {
			errMsg = "unknown"
		}
		errReason = fmt.Errorf("rego eval error: %s", errMsg)
	default:
		errReason = fmt.Errorf("rego result invalid: bad status %q", status)
	}
	if errReason != nil {
		return NewCheckError(RegoEvaluator, rule, benchmark, errReason)
	}
	eventData, _ := m["data"].(map[string]interface{})
	resourceID, _ := m["resource_id"].(string)
	resourceType, _ := m["resource_type"].(string)
	return NewCheckEvent(
		RegoEvaluator, result, eventData, resourceID, resourceType, rule, benchmark,
	)
}

func buildRegoModules(rootDir string, rule *Rule) (map[string]string, error) {
	modules := map[string]string{
		"datadog_helpers.rego": regoHelpersSource,
	}
	ruleFilename := fmt.Sprintf("%s.rego", rule.ID)
	ruleCode, err := loadFile(rootDir, ruleFilename)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(ruleCode) > 0 {
		modules[ruleFilename] = string(ruleCode)
	}
	for _, name := range rule.Imports {
		if _, ok := modules[name]; ok {
			continue
		}
		source, err := loadFile(rootDir, name)
		if err != nil {
			return nil, err
		}
		modules[name] = string(source)
	}
	return modules, nil
}

const regoHelpersSource = `package datadog

raw_finding(status, resource_type, resource_id, event_data) = f {
	f := {
		"status": status,
		"resource_type": resource_type,
		"resource_id": resource_id,
		"data": event_data,
	}
}

passed_finding(resource_type, resource_id, event_data) = f {
	f := raw_finding("passed", resource_type, resource_id, event_data)
}

failing_finding(resource_type, resource_id, event_data) = f {
	f := raw_finding("failing", resource_type, resource_id, event_data)
}

error_finding(resource_type, resource_id, error_msg) = f {
	f := raw_finding("error", resource_type, resource_id, {
		"error": error_msg
	})
}
`

var regoBuiltins = []func(*rego.Rego){
	rego.Function1(
		&rego.Function{
			Name: "parse_octal",
			Decl: regotypes.NewFunction(regotypes.Args(regotypes.S), regotypes.N),
		},
		func(_ rego.BuiltinContext, a *regoast.Term) (*regoast.Term, error) {
			str, ok := a.Value.(regoast.String)
			if !ok {
				return nil, fmt.Errorf("rego builtin parse_octal was not given a String")
			}
			value, err := strconv.ParseInt(string(str), 8, 0)
			if err != nil {
				return nil, fmt.Errorf("rego builtin parse_octal failed to parse into int: %w", err)
			}
			return regoast.IntNumberTerm(int(value)), err
		},
	),
}
