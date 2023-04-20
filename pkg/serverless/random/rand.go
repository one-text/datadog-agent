// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package random

import (
	cryptorand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/DataDog/datadog-agent/pkg/serverless/tags"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// Random holds a thread-safe source of random numbers.
var Random *rand.Rand

func init() {
	var seed int64
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(math.MaxInt64))
	if err == nil {
		seed = n.Int64()
	} else {
		log.Warnf("cannot generate random seed: %v; using current time", err)
		seed = time.Now().UnixNano()
	}
	Random = rand.New(&safeSource{
		source: rand.NewSource(seed),
	})
}

// safeSource holds a thread-safe implementation of rand.Source64.
type safeSource struct {
	source rand.Source
	sync.Mutex
}

func (rs *safeSource) Int63() int64 {
	rs.Lock()
	n := rs.source.Int63()
	rs.Unlock()

	return n
}

func (rs *safeSource) Uint64() uint64 { return uint64(rs.Int63()) }

func (rs *safeSource) Seed(seed int64) {
	rs.Lock()
	rs.source.Seed(seed)
	rs.Unlock()
}

// GenerateSpanId creates a secure random span id in specific scenarios,
// otherwise return a pseudo random id
func GenerateSpanId() uint64 {
	isSnapStart := os.Getenv(tags.InitType) == tags.SnapStartValue
	if isSnapStart {
		max := new(big.Int).SetUint64(math.MaxUint64)
		if randId, err := cryptorand.Int(cryptorand.Reader, max); err != nil {
			log.Debugf("Failed to generate a secure random span id: %v", err)
		} else {
			return randId.Uint64()
		}
	}
	return Random.Uint64()
}

// GenerateTraceId creates a secure random trace id in specific scenarios,
// otherwise return a pseudo random id
func GenerateTraceId() uint64 {
	return GenerateSpanId()
}
