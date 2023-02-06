// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build docker
// +build docker

package compliance

import (
	"context"

	"github.com/DataDog/datadog-agent/pkg/config"
	dockerutil "github.com/DataDog/datadog-agent/pkg/util/docker"
	docker "github.com/docker/docker/client"
)

func newDockerClient(ctx context.Context) (docker.CommonAPIClient, error) {
	if !config.IsDockerRuntime() {
		return nil, ErrIncompatibleEnvironment
	}
	return dockerutil.ConnectToDocker(ctx)
}
