// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	spdxBOMFileName = "sbom.spdx.json"
	spdxNoAssertion = "NOASSERTION"
	spdxDocumentID  = "SPDXRef-DOCUMENT"
)

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// marshalSPDXBOM renders the component inventory as an SPDX 2.3 document
// describing the same components as the CycloneDX document.
//
// SPDX requires a creation timestamp and a document namespace, neither of which
// CycloneDX makes mandatory. Both are derived rather than sampled: the timestamp
// follows the reproducible-builds SOURCE_DATE_EPOCH convention, and the
// namespace is a function of the inventory itself, so identical staged contents
// still produce identical bytes.
func marshalSPDXBOM(packageName string, components []bomComponent) ([]byte, error) {
	created, err := spdxCreatedTimestamp()
	if err != nil {
		return nil, err
	}

	packages := make([]spdxPackage, 0, len(components))
	relationships := make([]spdxRelationship, 0, len(components))

	for index, component := range components {
		// The inventory is already canonically sorted, so positional identifiers
		// are stable across builds of identical contents.
		identifier := fmt.Sprintf("SPDXRef-Package-%d", index)

		spdxComponent := spdxPackage{
			SPDXID:           identifier,
			Name:             component.Name,
			VersionInfo:      component.Version,
			DownloadLocation: spdxNoAssertion,
			FilesAnalyzed:    false,
			LicenseConcluded: spdxNoAssertion,
			LicenseDeclared:  spdxNoAssertion,
			CopyrightText:    spdxNoAssertion,
		}
		if component.PURL != "" {
			spdxComponent.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  component.PURL,
			}}
		}

		packages = append(packages, spdxComponent)
		relationships = append(relationships, spdxRelationship{
			SPDXElementID:      spdxDocumentID,
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: identifier,
		})
	}

	document := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            spdxDocumentID,
		Name:              packageName,
		DocumentNamespace: spdxDocumentNamespace(packageName, components),
		CreationInfo: spdxCreationInfo{
			Created: created,
			// The tool is named without a version: a version would change the
			// document on every release even when the contents are identical.
			Creators: []string{"Organization: OpenTelemetry", "Tool: opentelemetry-packaging"},
		},
		Packages:      packages,
		Relationships: relationships,
	}

	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling SPDX BOM: %w", err)
	}
	return append(data, '\n'), nil
}

// spdxCreatedTimestamp honours SOURCE_DATE_EPOCH when the build sets it, and
// otherwise pins the epoch, so the field never records wall-clock build time.
func spdxCreatedTimestamp() (string, error) {
	epoch := int64(0)
	if raw := strings.TrimSpace(os.Getenv("SOURCE_DATE_EPOCH")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return "", fmt.Errorf("parsing SOURCE_DATE_EPOCH %q: %w", raw, err)
		}
		epoch = parsed
	}
	return time.Unix(epoch, 0).UTC().Format("2006-01-02T15:04:05Z"), nil
}

// spdxDocumentNamespace derives the required unique namespace from the inventory
// it describes, so it is both reproducible and distinct for distinct contents.
func spdxDocumentNamespace(packageName string, components []bomComponent) string {
	digest := sha256.New()
	for _, component := range components {
		fmt.Fprintf(digest, "%s\x00%s\x00%s\x00%s\n",
			component.Type, component.Name, component.Version, component.PURL)
	}
	return fmt.Sprintf("https://opentelemetry.io/spdxdocs/%s-%x", packageName, digest.Sum(nil)[:8])
}
