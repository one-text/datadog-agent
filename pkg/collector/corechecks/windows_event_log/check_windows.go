// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package evtlog

import (
	"fmt"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/windows"
	"github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/subscription"

	"golang.org/x/sys/windows"
)

const checkName = "windows_event_log"

// The lower cased version of the `API SOURCE ATTRIBUTE` column from the table located here:
// https://docs.datadoghq.com/integrations/faq/list-of-api-source-attribute-value/
const sourceTypeName = "event viewer"

type Check struct {
	// check
	core.CheckBase
	config Config

	// event metrics
	event_priority metrics.EventPriority

	// event log
	sub *evtsubscribe.PullSubscription
	evtapi evtapi.API
	systemRenderContext evtapi.EventRenderContextHandle
}

type Config struct {
	instance instanceConfig
	init initConfig
}

type instanceConfig struct {
	ChannelPath string `yaml:"path"`
	Query string `yaml:query`
	Start string `yaml:start`
	Timeout uint `yaml:timeout`
	Payload_size uint `yaml:payload_size`
	Bookmark_frequency int `yaml:bookmark_frequency`
	Legacy_mode bool `yaml:legacy_mode`
	Event_priority string `yaml:event_priority`
}

type initConfig struct {
}

// Run executes the check
func (c *Check) Run() error {
	sender, err := c.GetSender()
	if err != nil {
		return err
	}

	// Fetch new events
	for {
		events, err := c.sub.GetEvents()
		if err != nil {
			return err
		}
		if events == nil {
			// no more events
			break
		}
		for _,winevent := range events {
			// Base event
			ddevent := metrics.Event{
				Priority:       c.event_priority,
				SourceTypeName: sourceTypeName,
				Tags:           []string{},
			}

			// Render Windows event values into the DD event
			c.renderEventSystemValues(winevent, &ddevent)
			c.renderEventMessage(winevent, &ddevent)

			// submit
			sender.Event(ddevent)

			// cleanup
			evtapi.EvtCloseRecord(c.evtapi, winevent.EventRecordHandle)
		}
		break
	}

	sender.Commit()
	return nil
}

func alertTypeFromLevel(level uint64) (metrics.EventAlertType, error) {
	// https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-leveltype-complextype#remarks
	// https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-eventdefinitiontype-complextype#attributes
	// > If you do not specify a level, the event descriptor will contain a zero for level.
	var alertType string
	switch level {
	case 0:
		alertType = "info"
	case 1:
		alertType = "error"
	case 2:
		alertType = "error"
	case 3:
		alertType = "warning"
	case 4:
		alertType = "info"
	case 5:
		alertType = "info"
	default:
		return metrics.EventAlertTypeInfo, fmt.Errorf("Invalid event level: '%d'", level)
	}

	return metrics.GetAlertTypeFromString(alertType)
}

func (c *Check) renderEventSystemValues(winevent *evtapi.EventRecord, ddevent *metrics.Event) error {
	// Render the values
	vals, err := c.evtapi.EvtRenderEventValues(c.systemRenderContext, winevent.EventRecordHandle)
	if err != nil {
		return fmt.Errorf("failed to render values: %v", err)
	}
	defer vals.Close()

	// Timestamp
	ts, err := vals.Time(evtapi.EvtSystemTimeCreated)
	if err != nil {
		// if no timestamp default to current time
		ts = time.Now().Unix()
	}
	ddevent.Ts = ts
	// FQDN
	fqdn, err := vals.String(evtapi.EvtSystemComputer)
	if err != nil {
		// default to DD hostname
		// TODO: how to get? python self.hostname
	}
	ddevent.Host = fqdn
	// Level
	level, err := vals.UInt(evtapi.EvtSystemLevel)
	if err == nil {
		// python compat: only set AlertType if level exists
		alertType, err := alertTypeFromLevel(level)
		if err != nil {
			// if not a valid level, default to error
			alertType, err = metrics.GetAlertTypeFromString("error")
		}
		if err == nil {
			ddevent.AlertType = alertType
		}
	}

	// Provider
	providerName, err := vals.String(evtapi.EvtSystemProviderName)
	if err == nil {
		ddevent.AggregationKey = providerName
		ddevent.Title = fmt.Sprintf("%s/%s", c.config.instance.ChannelPath, providerName)
	}

	return nil
}

func (c *Check) renderEventMessage(winevent *evtapi.EventRecord, ddevent *metrics.Event) error {
	// TODO: switch to evtformatmessage
	xml, err := c.evtapi.EvtRenderEventXml(winevent.EventRecordHandle)
	if err != nil {
		return err
	}

	ddevent.Text = windows.UTF16ToString(xml)

	return nil
}

func (c *Check) Configure(integrationConfigDigest uint64, data integration.Data, initConfig integration.Data, source string) error {
	err := c.CommonConfigure(integrationConfigDigest, initConfig, data, source)
	if err != nil {
		return err
	}

	// Default values
	c.config.instance.Timeout = 5
	c.config.instance.Legacy_mode = false
	c.config.instance.Payload_size = 10
	c.config.instance.Bookmark_frequency = 10
	c.config.instance.Query = "*"
	c.config.instance.Start = "now"
	c.config.instance.Event_priority = "normal"

	// Parse config
	err = yaml.Unmarshal(data, &c.config.instance)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(initConfig, &c.config.init)
	if err != nil {
		return err
	}

	// Validate config
	if len(c.config.instance.ChannelPath) == 0 {
		return fmt.Errorf("instance config `path` must not be empty")
	}
	if c.config.instance.Start != "now" && c.config.instance.Start != "old" {
		return fmt.Errorf("invalid instance config `start`: '%s'", c.config.instance.Start)
	}

	// Default values
	if len(c.config.instance.Query) == 0 {
		c.config.instance.Query = "*"
	}

	// map config options to check options
	c.event_priority, err = metrics.GetEventPriorityFromString(c.config.instance.Event_priority)
	if err != nil {
		return err
	}

	// Create the subscription
	opts := []evtsubscribe.PullSubscriptionOption{}
	if c.evtapi != nil {
		opts = append(opts, evtsubscribe.WithWindowsEventLogAPI(c.evtapi))
	}
	if c.config.instance.Start == "old" {
		opts = append(opts, evtsubscribe.WithStartAtOldestRecord())
	}

	opts = append(opts, evtsubscribe.WithEventBatchCount(c.config.instance.Payload_size))

	c.sub = evtsubscribe.NewPullSubscription(
		c.config.instance.ChannelPath,
		c.config.instance.Query,
		opts...)

	// Start the subscription
	err = c.sub.Start()
	if err != nil {
		return fmt.Errorf("Failed to subscribe to events: %v", err)
	}

	// Create a render context for System event values
	c.systemRenderContext, err = c.evtapi.EvtCreateRenderContext(nil, evtapi.EvtRenderContextSystem)
	if err != nil {
		//return err
	}

	return nil
}

func (c *Check) Cancel() {
	if c.sub != nil {
		c.sub.Stop()
	}

	if c.systemRenderContext != evtapi.EventRenderContextHandle(0) {
		c.evtapi.EvtClose(windows.Handle(c.systemRenderContext))
	}
}

func checkFactory() check.Check {
	return &Check{
		CheckBase: core.NewCheckBase(checkName),
		evtapi: winevtapi.New(),
	}
}

func init() {
	core.RegisterCheck(checkName, checkFactory)
}