// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package profile

import (
	"sync"

	"golang.org/x/exp/slices"

	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/activity_tree"
	"github.com/DataDog/datadog-agent/pkg/security/security_profile/dump"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// SecurityProfile defines a security profile
type SecurityProfile struct {
	sync.Mutex
	loadedInKernel         bool
	selector               cgroupModel.WorkloadSelector
	profileCookie          uint64
	anomalyDetectionEvents []model.EventType

	// Instances is the list of workload instances to witch the profile should apply
	Instances []*cgroupModel.CacheEntry

	// Status is the status of the profile
	Status model.Status

	// Version is the version of a Security Profile
	Version string

	// Metadata contains metadata for the current profile
	Metadata dump.Metadata

	// Tags defines the tags used to compute this profile
	Tags []string

	// Syscalls is the syscalls profile
	Syscalls []uint32

	// ActivityTree contains the activity tree of the Security Profile
	ActivityTree *activity_tree.ActivityTree
}

// NewSecurityProfile creates a new instance of Security Profile
func NewSecurityProfile(selector cgroupModel.WorkloadSelector, anomalyDetectionEvents []model.EventType) *SecurityProfile {
	return &SecurityProfile{
		selector:               selector,
		anomalyDetectionEvents: anomalyDetectionEvents,
	}
}

// reset empties all internal fields so that this profile can be used again in the future
func (p *SecurityProfile) reset() {
	p.loadedInKernel = false
	p.Instances = nil
}

// generateCookies computes random cookies for all the entries in the profile that require one
func (p *SecurityProfile) generateCookies() {
	p.profileCookie = utils.RandNonZeroUint64()

	// TODO: generate cookies for all the nodes in the activity tree
}

func (p *SecurityProfile) generateSyscallsFilters() [64]byte {
	var output [64]byte
	for _, syscall := range p.Syscalls {
		if syscall/8 < 64 && (1<<(syscall%8) < 256) {
			output[syscall/8] |= 1 << (syscall % 8)
		}
	}
	return output
}

func (p *SecurityProfile) generateKernelSecurityProfileDefinition() [16]byte {
	var output [16]byte
	model.ByteOrder.PutUint64(output[0:8], p.profileCookie)
	model.ByteOrder.PutUint32(output[8:12], uint32(p.Status))
	return output
}

// MatchesSelector is used to control how an event should be added to a profile
func (p *SecurityProfile) MatchesSelector(entry *model.ProcessCacheEntry) bool {
	for _, workload := range p.Instances {
		if entry.ContainerID == workload.ID {
			return true
		}
	}
	return false
}

// IsEventTypeValid is used to control which event types should trigger anomaly detection alerts
func (p *SecurityProfile) IsEventTypeValid(evtType model.EventType) bool {
	return slices.Contains[model.EventType](p.anomalyDetectionEvents, evtType)
}

// NewProcessNodeCallback is a callback function used to propagate the fact that a new process node was added to the activity tree
func (p *SecurityProfile) NewProcessNodeCallback(node *activity_tree.ProcessNode) {
	// TODO: debounce and regenerate profile filters & programs
}

// IsAnomalyDetectionEvent returns true for the event types that have a security profile context
func IsAnomalyDetectionEvent(eventyType model.EventType) bool {
	return slices.Contains([]model.EventType{
		model.AnomalyDetectionSyscallEventType,
	}, eventyType)
}
