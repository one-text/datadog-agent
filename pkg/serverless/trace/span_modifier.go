// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package trace

import (
	"github.com/DataDog/datadog-agent/pkg/serverless/trace/inferredspan"
	"github.com/DataDog/datadog-agent/pkg/trace/pb"
	"github.com/DataDog/datadog-agent/pkg/util/log"

	"go.uber.org/atomic"
)

type spanModifier struct {
	tags  map[string]string
	count *atomic.Int32
}

// Process applies extra logic to the given span
func (s *spanModifier) ModifySpan(span *pb.Span) {
	if span.Service == "aws.lambda" && s.tags["service"] != "" {
		// service name could be incorrectly set to 'aws.lambda' in datadog lambda libraries
		span.Service = s.tags["service"]
	}
	if inferredspan.CheckIsInferredSpan(span) {
		log.Debug("Detected a managed service span, filtering out function tags")

		// filter out existing function tags inside span metadata
		spanMetadataTags := span.Meta
		if spanMetadataTags != nil {
			spanMetadataTags = inferredspan.FilterFunctionTags(spanMetadataTags)
			span.Meta = spanMetadataTags
		}
	}
	if s.count != nil {
		s.count.Inc()
	}

}

func (s *spanModifier) Reset() {
	s.count.Store(0)
}

func (s *spanModifier) GetSpanCount() int32 {
	return s.count.Load()
}
