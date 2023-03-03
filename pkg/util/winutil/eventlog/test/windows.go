// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package eventlog_test

import (
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

    evtapidef "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api"
    winevtapi "github.com/DataDog/datadog-agent/pkg/util/winutil/eventlog/api/windows"
)

const (
	eventLogRootKey = `SYSTEM\CurrentControlSet\Services\EventLog`
)

// WindowsTestInterface uses the real Windows EventLog APIs
// and provides utilities to the test framework that will modify
// the host system (e.g. install event log source, generate events).
type WindowsTestInterface struct {
	t testing.TB
	eventlogapi *winevtapi.WindowsEventLogAPI
}

func NewWindowsTestInterface(t testing.TB) *WindowsTestInterface {
	var ti WindowsTestInterface
	ti.t = t
	ti.eventlogapi = winevtapi.NewWindowsEventLogAPI()
	return &ti
}

func (ti *WindowsTestInterface) Name() string{
	return "Windows"
}

func (ti *WindowsTestInterface) T() testing.TB {
	return ti.t
}

func (ti *WindowsTestInterface) EventLogAPI() evtapidef.IWindowsEventLogAPI {
	return ti.eventlogapi
}

func (ti *WindowsTestInterface) InstallChannel(channel string) error {
	// Open EventLog registry key
	rootKey, err := registry.OpenKey(registry.LOCAL_MACHINE, channelRootKey(), registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer rootKey.Close()

	// Create the channel subkey
	channelKey, _, err := registry.CreateKey(rootKey, channel, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer channelKey.Close()

	return nil
}

func (ti *WindowsTestInterface) InstallSource(channel string, source string) error {
	// Open channel key
	channelKey, err := registry.OpenKey(registry.LOCAL_MACHINE, channelRegistryKey(channel), registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer channelKey.Close()

	// Create the source subkey
	sourceKey, _, err := registry.CreateKey(channelKey, source, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer sourceKey.Close()


	err = sourceKey.SetExpandStringValue("EventMessageFile", `C:\Windows\System32\eventcreate.exe`)
	if err != nil {
		return err
	}
	err = sourceKey.SetDWordValue("TypesSupported", windows.EVENTLOG_INFORMATION_TYPE|windows.EVENTLOG_WARNING_TYPE|windows.EVENTLOG_ERROR_TYPE)
	if err != nil {
		return err
	}

	return nil
}

func (ti *WindowsTestInterface) RemoveChannel(channel string) error {
	// Open EventLog registry key
	rootKey, err := registry.OpenKey(registry.LOCAL_MACHINE, channelRootKey(), registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer rootKey.Close()

	// Delete channel subkey
	return registry.DeleteKey(rootKey, channel)
}

func (ti *WindowsTestInterface) RemoveSource(channel string, source string) error {
	// Open channel key
	channelKey, err := registry.OpenKey(registry.LOCAL_MACHINE, channelRegistryKey(channel), registry.CREATE_SUB_KEY)
	if err != nil {
		return err
	}
	defer channelKey.Close()

	// Delete source subkey
	return registry.DeleteKey(channelKey, source)
}

func (ti *WindowsTestInterface) GenerateEvents(channelName string, numEvents uint) error {

	sourceHandle, err := ti.eventlogapi.RegisterEventSource(channelName)
	if err != nil {
		return err
	}
	defer ti.eventlogapi.DeregisterEventSource(sourceHandle)

	for i := uint(0); i < numEvents; i+=1 {
		err := ti.eventlogapi.ReportEvent(
			sourceHandle,
			windows.EVENTLOG_INFORMATION_TYPE,
			0, 1000, []string{"teststring"}, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

func channelRootKey() string {
	return eventLogRootKey
}

func channelRegistryKey(channel string) string {
	return fmt.Sprintf(`%v\%v`, channelRootKey(), channel)
}

func sourceRegistryKey(channel string, source string) string {
	return fmt.Sprintf(`%v\%v`, channelRegistryKey(channel), source)
}
