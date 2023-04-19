// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package testutil

import (
	"os"
	"strings"
)

var tracePipe *os.File
var ebpfTracePipeData []string

func closeTracePipe() {
	if tracePipe != nil {
		tracePipe.Close()
	}
	tracePipe = nil
}

func StartEBPFTrace() {
	go func() {
		var err error
		closeTracePipe()
		tracePipe, err = os.Open("/sys/kernel/debug/tracing/trace_pipe")
		if err != nil {
			return
		}
		defer closeTracePipe()
		buf := make([]byte, 4096)
		for {
			n, err := tracePipe.Read(buf)
			if err != nil {
				break
			}
			ebpfTracePipeData = append(ebpfTracePipeData, string(buf[:n]))
		}

	}()
}

func StopEBPFTrace() string {
	closeTracePipe()
	r := strings.Join(ebpfTracePipeData, "")
	ebpfTracePipeData = []string{}
	return r
}
