// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"encoding/json"
	"fmt"
)

const cycloneDXBOMFileName = "sbom.cdx.json"

type cycloneDXBOM struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Version     int                  `json:"version"`
	Components  []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// marshalCycloneDXBOM renders the component inventory as a CycloneDX 1.6
// document. The package name is not recorded: this document is a flat inventory,
// and declaring its own subject through metadata.component is tracked separately.
func marshalCycloneDXBOM(_ string, components []bomComponent) ([]byte, error) {
	cycloneDXComponents := make([]cycloneDXComponent, 0, len(components))
	for _, component := range components {
		cycloneDXComponents = append(cycloneDXComponents, cycloneDXComponent{
			Type:    component.Type,
			Name:    component.Name,
			Version: component.Version,
			PURL:    component.PURL,
		})
	}

	// CycloneDX permits serialNumber and metadata.timestamp, but neither is
	// useful for this installed component inventory. Leaving them out keeps the
	// generated file byte-for-byte reproducible for identical staged contents.
	bom := cycloneDXBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Components:  cycloneDXComponents,
	}

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling CycloneDX BOM: %w", err)
	}
	return append(data, '\n'), nil
}
