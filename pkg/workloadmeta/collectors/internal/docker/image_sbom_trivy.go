// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build docker && trivy
// +build docker,trivy

package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	"github.com/DataDog/datadog-agent/pkg/sbom/collectors/docker"
	"github.com/DataDog/datadog-agent/pkg/sbom/scanner"
	dutil "github.com/DataDog/datadog-agent/pkg/util/docker"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

func imageMetadataCollectionIsEnabled() bool {
	return config.Datadog.GetBool("container_image_collection.metadata.enabled")
}

func sbomCollectionIsEnabled() bool {
	return imageMetadataCollectionIsEnabled() && config.Datadog.GetBool("container_image_collection.sbom.enabled")
}

func (c *collector) startSBOMCollection(ctx context.Context) error {
	if !sbomCollectionIsEnabled() {
		return nil
	}

	var err error
	enabledAnalyzers := config.Datadog.GetStringSlice("container_image_collection.sbom.analyzers")
	c.scanOptions = sbom.ScanOptions{
		Analyzers: enabledAnalyzers,
		Timeout:   scanningTimeout(),
		WaitAfter: timeBetweenScans(),
	}

	c.trivyScanner = scanner.GetGlobalScanner()
	if c.trivyScanner == nil {
		return fmt.Errorf("error initializing trivy client: %w", err)
	}

	imgEventsCh := c.store.Subscribe(
		"SBOM collector",
		workloadmeta.NormalPriority,
		workloadmeta.NewFilter(
			[]workloadmeta.Kind{workloadmeta.KindContainerImageMetadata},
			workloadmeta.SourceAll,
			workloadmeta.EventTypeSet,
		),
	)

	go func() {
		for {
			select {
			// We don't want to keep scanning if image channel is not empty but context is expired
			case <-ctx.Done():
				return

			case eventBundle := <-imgEventsCh:
				close(eventBundle.Ch)

				for _, event := range eventBundle.Events {
					image := event.Entity.(*workloadmeta.ContainerImageMetadata)

					if image.SBOM != nil {
						// BOM already stored. Can happen when the same image ID
						// is referenced with different names.
						log.Debugf("Image: %s/%s (id %s) SBOM already available", image.Namespace, image.Name, image.ID)
						continue
					}

					scanContext, cancel := context.WithTimeout(ctx, scanningTimeout())
					if err := c.extractBOMWithTrivy(scanContext, image); err != nil {
						log.Warnf("Error extracting SBOM for image: namespace=%s name=%s, err: %s", image.Namespace, image.Name, err)
					}

					cancel()
				}
			}
		}
	}()

	return nil
}

func (c *collector) extractBOMWithTrivy(ctx context.Context, storedImage *workloadmeta.ContainerImageMetadata) error {
	scanRequest := &docker.ScanRequest{
		ImageMeta:      storedImage,
		FromFilesystem: config.Datadog.GetBool("container_image_collection.sbom.use_mount"),
	}

	ch := make(chan sbom.ScanResult)
	if err := c.trivyScanner.Scan(scanRequest, c.scanOptions, ch); err != nil {
		return err
	}

	go func() {
		select {
		case <-ctx.Done():
		case result := <-ch:
			bom, err := result.Report.ToCycloneDX()
			if err != nil {
				log.Errorf("Failed to extract SBOM from report")
				return
			}

			sbom := &workloadmeta.SBOM{
				CycloneDXBOM:       bom,
				GenerationTime:     result.CreatedAt,
				GenerationDuration: result.Duration,
			}

			// Updating workloadmeta entities directly is not thread-safe, that's why we
			// generate an update event here instead.
			event := &dutil.ImageEvent{
				ImageID:   storedImage.ID,
				Action:    dutil.ImageEventActionSbom,
				Timestamp: time.Now(),
			}
			if err := c.handleImageEvent(ctx, event, sbom); err != nil {
				log.Warnf("Error extracting SBOM for image: namespace=%s name=%s, err: %s", storedImage.Namespace, storedImage.Name, err)
			}
		}
	}()

	return nil
}

func scanningTimeout() time.Duration {
	return time.Duration(config.Datadog.GetInt("container_image_collection.sbom.scan_timeout")) * time.Second
}

func timeBetweenScans() time.Duration {
	return time.Duration(config.Datadog.GetInt("container_image_collection.sbom.scan_interval")) * time.Second
}