// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package builder

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalSPDXBOMDescribesEveryComponent(t *testing.T) {
	components, err := canonicalBOMComponents(unorderedTestComponents())
	require.NoError(t, err)

	data, err := marshalSPDXBOM("opentelemetry-nodejs-autoinstrumentation", components)
	require.NoError(t, err)

	var document spdxDocument
	require.NoError(t, json.Unmarshal(data, &document))

	assert.Equal(t, "SPDX-2.3", document.SPDXVersion)
	assert.Equal(t, "CC0-1.0", document.DataLicense)
	assert.Equal(t, spdxDocumentID, document.SPDXID)
	assert.Equal(t, "opentelemetry-nodejs-autoinstrumentation", document.Name)
	assert.NotEmpty(t, document.DocumentNamespace)
	assert.NotEmpty(t, document.CreationInfo.Created)
	assert.NotEmpty(t, document.CreationInfo.Creators)

	require.Len(t, document.Packages, 2)
	assert.Equal(t, "alpha", document.Packages[0].Name)
	assert.Equal(t, "1.0.0", document.Packages[0].VersionInfo)
	require.Len(t, document.Packages[0].ExternalRefs, 1)
	assert.Equal(t, "purl", document.Packages[0].ExternalRefs[0].ReferenceType)
	assert.Equal(t, "pkg:npm/alpha@1.0.0", document.Packages[0].ExternalRefs[0].ReferenceLocator)

	// Every package must be reachable from the document, or consumers cannot
	// tell which packages the document actually asserts.
	require.Len(t, document.Relationships, len(document.Packages))
	for index, relationship := range document.Relationships {
		assert.Equal(t, spdxDocumentID, relationship.SPDXElementID)
		assert.Equal(t, "DESCRIBES", relationship.RelationshipType)
		assert.Equal(t, document.Packages[index].SPDXID, relationship.RelatedSPDXElement)
	}
}

func TestMarshalSPDXBOMOmitsPURLWhenUnknown(t *testing.T) {
	data, err := marshalSPDXBOM("opentelemetry-java-autoinstrumentation", []bomComponent{
		{Type: "library", Name: "opentelemetry-javaagent", Version: "2.15.0"},
	})
	require.NoError(t, err)

	var document spdxDocument
	require.NoError(t, json.Unmarshal(data, &document))
	require.Len(t, document.Packages, 1)
	assert.Empty(t, document.Packages[0].ExternalRefs)
	assert.Equal(t, spdxNoAssertion, document.Packages[0].DownloadLocation)
}

func TestMarshalSPDXBOMIsDeterministic(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")

	components, err := canonicalBOMComponents(unorderedTestComponents())
	require.NoError(t, err)

	first, err := marshalSPDXBOM("opentelemetry-nodejs-autoinstrumentation", components)
	require.NoError(t, err)
	second, err := marshalSPDXBOM("opentelemetry-nodejs-autoinstrumentation", components)
	require.NoError(t, err)

	assert.Equal(t, string(first), string(second))

	// With no SOURCE_DATE_EPOCH the timestamp is pinned, never sampled from the
	// wall clock, which is what keeps rebuilds byte-identical.
	var document spdxDocument
	require.NoError(t, json.Unmarshal(first, &document))
	assert.Equal(t, "1970-01-01T00:00:00Z", document.CreationInfo.Created)
}

func TestSPDXCreatedTimestampHonoursSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	created, err := spdxCreatedTimestamp()
	require.NoError(t, err)
	assert.Equal(t, "2023-11-14T22:13:20Z", created)

	t.Setenv("SOURCE_DATE_EPOCH", "not-a-number")
	_, err = spdxCreatedTimestamp()
	require.Error(t, err)
}

func TestSPDXDocumentNamespaceTracksContents(t *testing.T) {
	base := []bomComponent{{Type: "library", Name: "alpha", Version: "1.0.0", PURL: "pkg:npm/alpha@1.0.0"}}
	changed := []bomComponent{{Type: "library", Name: "alpha", Version: "1.0.1", PURL: "pkg:npm/alpha@1.0.1"}}

	assert.Equal(t,
		spdxDocumentNamespace("pkg", base),
		spdxDocumentNamespace("pkg", base),
	)
	assert.NotEqual(t,
		spdxDocumentNamespace("pkg", base),
		spdxDocumentNamespace("pkg", changed),
	)
}

// TestBOMFormatsAgreeOnContents is the invariant that makes shipping two formats
// safe: both documents are projections of one inventory, so they can never
// disagree about which components the package bundles.
func TestBOMFormatsAgreeOnContents(t *testing.T) {
	staging := t.TempDir()
	const packageName = "opentelemetry-nodejs-autoinstrumentation"

	contents, err := writeInstalledBOMs(staging, packageName, unorderedTestComponents())
	require.NoError(t, err)
	require.Len(t, contents, 2)

	documents := make(map[string]string, len(contents))
	for _, content := range contents {
		data, err := os.ReadFile(content.Source)
		require.NoError(t, err)
		documents[content.Destination] = string(data)
	}

	var cycloneDX cycloneDXBOM
	require.NoError(t, json.Unmarshal(
		[]byte(documents["/usr/share/doc/"+packageName+"/"+cycloneDXBOMFileName]), &cycloneDX))

	var spdx spdxDocument
	require.NoError(t, json.Unmarshal(
		[]byte(documents["/usr/share/doc/"+packageName+"/"+spdxBOMFileName]), &spdx))

	type identity struct{ name, version, purl string }

	fromCycloneDX := make([]identity, 0, len(cycloneDX.Components))
	for _, component := range cycloneDX.Components {
		fromCycloneDX = append(fromCycloneDX, identity{component.Name, component.Version, component.PURL})
	}

	fromSPDX := make([]identity, 0, len(spdx.Packages))
	for _, component := range spdx.Packages {
		purl := ""
		if len(component.ExternalRefs) == 1 {
			purl = component.ExternalRefs[0].ReferenceLocator
		}
		fromSPDX = append(fromSPDX, identity{component.Name, component.VersionInfo, purl})
	}

	assert.Equal(t, fromCycloneDX, fromSPDX)
}
