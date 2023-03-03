// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.
//go:build windows
// +build windows

package api

import (
	"golang.org/x/sys/windows"
)

const (
	// EVT_SUBSCRIBE_FLAGS
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_subscribe_flags
    EvtSubscribeToFutureEvents = iota + 1
    EvtSubscribeStartAtOldestRecord
    EvtSubscribeStartAfterBookmark
    EvtSubscribeOriginMask
    EvtSubscribeTolerateQueryErrors = 0x1000
    EvtSubscribeStrict = 0x10000
)

const (
	// EVT_RENDER_CONTEXT_FLAGS
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_render_context_flags
	EvtRenderContextValues = iota
	EvtRenderContextSystem
	EvtRenderContextUser
)

const (
	// EVT_RENDER_FLAGS
	// https://learn.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_render_flags
	EvtRenderEventValues = iota
	EvtRenderEventXml
	EvtRenderBookmark
)

// Returned from EvtQuery and EvtSubscribe
type EventResultSetHandle windows.Handle

// Returned from EvtNext
type EventRecordHandle windows.Handle

// Returned from EvtCreateBookmark
type EventBookmarkHandle windows.Handle

// Returned from EvtCreateRenderContext
type EventRenderContextHandle windows.Handle

// Returned from RegisterEventSource
type EventSourceHandle windows.Handle

// Returned from CreateEvent
type WaitEventHandle windows.Handle

type IWindowsEventLogAPI interface {
	// Windows Event Log API methods
	EvtSubscribe(
		SignalEvent WaitEventHandle,
		ChannelPath string,
		Query string,
		Bookmark EventBookmarkHandle,
		Flags uint) (EventResultSetHandle, error)

	EvtNext(
		Session EventResultSetHandle,
		EventsArray []EventRecordHandle,
		EventsSize uint,
		Timeout uint) ([]EventRecordHandle, error)

	EvtClose(h windows.Handle)

	EvtRenderEventXml(Fragment EventRecordHandle) ([]uint16, error)

	EvtRenderBookmark(Fragment EventBookmarkHandle) ([]uint16, error)

	// Windows Event Logging methods
	RegisterEventSource(SourceName string) (EventSourceHandle, error)

	DeregisterEventSource(EventLog EventSourceHandle) error

	EvtClearLog(ChannelPath string) error

	ReportEvent(
		EventLog EventSourceHandle,
		Type uint,
		Category uint,
		EventID uint,
		Strings []string,
		RawData []uint8) error

}


//
// Helpful wrappers for custom types
//
func EvtCloseResultSet(api IWindowsEventLogAPI, h EventResultSetHandle) {
	api.EvtClose(windows.Handle(h))
}

func EvtCloseBookmark(api IWindowsEventLogAPI, h EventBookmarkHandle) {
	api.EvtClose(windows.Handle(h))
}

func EvtCloseRecord(api IWindowsEventLogAPI, h EventRecordHandle) {
	api.EvtClose(windows.Handle(h))
}
