// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var validSPDXSBOMBytes = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "pkg",
      "versionInfo": "1.0.0"
    }
  ]
}
`)

var validCDXSBOMBytes = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [
      {
        "vendor": "anchore",
        "name": "syft",
        "version": "0.95.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "pkg",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0"
    }
  ]
}
`)

var invalidSPDX_WrongVersionType = []byte(`
{
  "spdxVersion": 2.3,
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "bad-doc"
}
`)

var invalidSPDX_MissingDocumentID = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "name": "bad-doc",
  "dataLicense": "CC0-1.0"
}
`)

var invalidSPDX_PackagesNotArray = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "bad-doc",
  "dataLicense": "CC0-1.0",
  "packages": {}
}
`)

var invalidCDX_MissingSpecVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "version": 0.1
}
`)

var invalidCDX_VersionWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": "one"
}
`)

var invalidCDX_ComponentsNotArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": {}
}
`)

var invalidCDX_BomFormatWrongType = []byte(`
{
  "bomFormat": "wrongSBOMFormat",
  "specVersion": "1.5",
  "version": 1
}
`)

// SPDX 3.0 SBOM with all basic fields
var validSPDX3CompleteSBOM = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "complete-spdx3-sbom",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package-App", "SPDXRef-Package-Lib", "SPDXRef-File-main"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2025-01-15T10:30:00Z",
      "createdBy": ["_:org1", "_:person1"],
      "createdUsing": ["_:tool1"]
    },
    {
      "type": "Organization",
      "@id": "_:org1",
      "name": "Example Organization",
      "email": "sbom@example.com"
    },
    {
      "type": "Person",
      "@id": "_:person1",
      "name": "John Doe",
      "email": "john@example.com"
    },
    {
      "type": "Tool",
      "@id": "_:tool1",
      "name": "syft-0.100.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package-App",
      "name": "my-application",
      "software_packageVersion": "1.0.0",
      "software_primaryPurpose": "application"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package-Lib",
      "name": "my-library",
      "software_packageVersion": "2.3.4",
      "software_primaryPurpose": "library"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File-main",
      "name": "/src/main.go"
    },
    {
      "type": "Relationship",
      "spdxId": "SPDXRef-Relationship-1",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-Package-App"],
      "relationshipType": "describes"
    },
    {
      "type": "Relationship",
      "spdxId": "SPDXRef-Relationship-2",
      "from": "SPDXRef-Package-App",
      "to": ["SPDXRef-Package-Lib"],
      "relationshipType": "dependsOn"
    },
    {
      "type": "Relationship",
      "spdxId": "SPDXRef-Relationship-3",
      "from": "SPDXRef-Package-App",
      "to": ["SPDXRef-File-main"],
      "relationshipType": "contains"
    }
  ]
}
`)

var invalidSPDX3_WrongContext = []byte(`
{
  "@context": "https://wrong-context.org/schema",
  "@graph": [
    {
      "type": "Document"
    }
  ]
}
`)

var spdx3_missing_context = []byte(`
{
  "name": "no-context-doc",
  "@graph": []
}
`)

var spdx3_context_as_string = []byte(`
{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT"
    }
  ]
}
`)

var spdx3_invalid_version_in_context = []byte(`
{
  "@context": "https://spdx.org/rdf/3.0.222/spdx-context.jsonld",
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT"
    }
  ]
}
`)

var spdx3_missing_CreationInfo = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT"
    }
  ]
}
`)

// A null entry inside an SPDX array decodes to a nil element, which used to be
// dereferenced while walking packages, files and relationships.
var spdxNullPackageEntry = []byte(`{"spdxVersion":"SPDX-2.1","SPDXID":"SPDXRef-DOCUMENT","name":"x","documentNamespace":"http://example.com/x","dataLicense":"CC0-1.0","creationInfo":{"created":"2020-01-01T00:00:00Z","creators":["Tool: t"]},"packages":[null]}`)

var spdxNullFileEntry = []byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"x","documentNamespace":"http://example.com/x","dataLicense":"CC0-1.0","creationInfo":{"created":"2020-01-01T00:00:00Z","creators":["Tool: t"]},"files":[null]}`)

var spdxNullRelationshipEntry = []byte(`{"spdxVersion":"SPDX-2.1","SPDXID":"SPDXRef-DOCUMENT","name":"x","documentNamespace":"http://example.com/x","dataLicense":"CC0-1.0","creationInfo":{"created":"2020-01-01T00:00:00Z","creators":["Tool: t"]},"relationships":[null]}`)

func TestNewSBOMDocumentFromBytes(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		input    []byte
		wantSpec SpecFormat
		wantErr  bool
	}{
		{
			name:     "valid SPDX SBOM",
			input:    validSPDXSBOMBytes,
			wantSpec: SBOMSpecSPDX,
			wantErr:  false,
		},
		{
			name:     "valid SPDX 3.0 complete SBOM",
			input:    validSPDX3CompleteSBOM,
			wantSpec: SBOMSpecSPDX,
			wantErr:  false,
		},
		{
			name:     "valid CycloneDX SBOM",
			input:    validCDXSBOMBytes,
			wantSpec: SBOMSpecCDX,
			wantErr:  false,
		},
		{
			name:     "spdx wrong spdxVersion type",
			input:    invalidSPDX_WrongVersionType,
			wantSpec: SBOMSpecUnknown,

			//  "error": "unsupported SDPX version: %!s(float64=2.3)"
			wantErr: true,
		},
		{
			name:     "spdx missing document SPDXID",
			input:    invalidSPDX_MissingDocumentID,
			wantSpec: SBOMSpecUnknown,

			// "error": "unsupported sbom format"
			wantErr: true,
		},
		{
			name:     "spdx packages not array",
			input:    invalidSPDX_PackagesNotArray,
			wantSpec: SBOMSpecUnknown,

			// "error": "json: cannot unmarshal object into Go struct field doc.packages of type []*v2_3.Package"
			wantErr: true,
		},
		{
			name:     "cdx missing specVersion",
			input:    invalidCDX_MissingSpecVersion,
			wantSpec: SBOMSpecUnknown,

			// "error": "json: cannot unmarshal number 0.1 into Go struct field BOM.version of type int"
			wantErr: true,
		},
		{
			name:     "cdx components not array",
			input:    invalidCDX_ComponentsNotArray,
			wantSpec: SBOMSpecUnknown,

			// "error": "json: cannot unmarshal object into Go struct field BOM.components of type []cyclonedx.Component"
			wantErr: true,
		},
		{
			name:     "bomFormat wrong type",
			input:    invalidCDX_BomFormatWrongType,
			wantSpec: SBOMSpecUnknown,

			// "error": "unsupported sbom format"
			wantErr: true,
		},
		{
			name:     "specVersion wrong type",
			input:    invalidCDX_VersionWrongType,
			wantSpec: SBOMSpecUnknown,

			// "error": "unsupported sbom format"
			wantErr: true,
		},
		{
			name:     "spdx3 wrong context",
			input:    invalidSPDX3_WrongContext,
			wantSpec: SBOMSpecUnknown,
			wantErr:  true,
		},
		{
			name:     "spdx3_missing_context",
			input:    spdx3_missing_context,
			wantSpec: SBOMSpecUnknown,
			wantErr:  true,
		},
		{
			name:     "spdx3_context_as_string",
			input:    spdx3_context_as_string,
			wantSpec: SBOMSpecSPDX,
			wantErr:  false, // JSON-LD allows string context, spdx_zen accepts it
		},
		{
			name:     "spdx3_invalid_version_in_context",
			input:    spdx3_invalid_version_in_context,
			wantSpec: SBOMSpecUnknown,
			wantErr:  true,
		},
		{
			name:     "spdx null package entry",
			input:    spdxNullPackageEntry,
			wantSpec: SBOMSpecSPDX,
			wantErr:  false,
		},
		{
			name:     "spdx null file entry",
			input:    spdxNullFileEntry,
			wantSpec: SBOMSpecSPDX,
			wantErr:  false,
		},
		{
			name:     "spdx null relationship entry",
			input:    spdxNullRelationshipEntry,
			wantSpec: SBOMSpecSPDX,
			wantErr:  false,
		},
		{
			name:     "spdx3_missing_CreationInfo",
			input:    spdx3_missing_CreationInfo,
			wantSpec: SBOMSpecSPDX,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := NewSBOMDocumentFromBytes(ctx, tt.input, Signature{})

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, doc)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, doc)

			assert.Equal(t, string(tt.wantSpec), doc.Spec().GetSpecType())
		})
	}
}

// TestSPDX3DocumentParsing tests comprehensive SPDX 3.0 document parsing
func TestSPDX3DocumentParsing(t *testing.T) {
	ctx := context.Background()

	doc, err := NewSBOMDocumentFromBytes(ctx, validSPDX3CompleteSBOM, Signature{})
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Check spec
	spec := doc.Spec()
	assert.Equal(t, "spdx", spec.GetSpecType())
	assert.True(t, strings.HasPrefix(spec.GetVersion(), "3.0"), "Version should start with 3.0")
	assert.Equal(t, "complete-spdx3-sbom", spec.GetName())
	assert.Equal(t, "SPDXRef-DOCUMENT", spec.GetSpdxID())
	assert.NotEmpty(t, spec.GetCreationTimestamp())

	// Check authors (should have both Person and Organization)
	authors := doc.Authors()
	assert.GreaterOrEqual(t, len(authors), 2)

	// Check tools
	tools := doc.Tools()
	assert.GreaterOrEqual(t, len(tools), 1)

	// Check components (packages) - should have 2 packages
	components := doc.Components()
	assert.GreaterOrEqual(t, len(components), 2)

	// Check files
	files := doc.Files()
	assert.GreaterOrEqual(t, len(files), 1)

	// Check primary component
	primary := doc.PrimaryComp()
	assert.NotNil(t, primary)

	// Check relationships
	relationships := doc.GetRelationships()
	assert.GreaterOrEqual(t, len(relationships), 2)
}

// TestSPDX3FormatDetection tests SPDX 3.0 format detection specifically
func TestSPDX3FormatDetection(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantDetected bool
		wantVersion  string
	}{
		{
			name:         "SPDX 3.0.1 context string",
			input:        []byte(`{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}`),
			wantDetected: true,
			wantVersion:  "SPDX-3.0.1",
		},
		{
			name:         "SPDX 3.0 context array",
			input:        []byte(`{"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"], "@graph": []}`),
			wantDetected: true,
			wantVersion:  "SPDX-3.0.1",
		},
		{
			name:         "non-SPDX context",
			input:        []byte(`{"@context": "https://example.org/other-context", "@graph": []}`),
			wantDetected: false,
			wantVersion:  "",
		},
		{
			name:         "SPDX 2.3 (no context)",
			input:        validSPDXSBOMBytes,
			wantDetected: true,
			wantVersion:  "SPDX-2.3",
		},
		{
			name:         "SPDX 3.0 context (not 3.0.1)",
			input:        []byte(`{"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld", "@graph": []}`),
			wantDetected: true,
			wantVersion:  "SPDX-3.0",
		},
		{
			name:         "Multiple contexts array SPDX first",
			input:        []byte(`{"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "https://other.org/context"], "@graph": []}`),
			wantDetected: true,
			wantVersion:  "SPDX-3.0.1",
		},
		{
			name:         "Multiple contexts array SPDX last",
			input:        []byte(`{"@context": ["https://other.org/context", "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"], "@graph": []}`),
			wantDetected: true,
			wantVersion:  "SPDX-3.0.1",
		},
		{
			name:         "Empty context array",
			input:        []byte(`{"@context": [], "@graph": []}`),
			wantDetected: false,
			wantVersion:  "",
		},
		{
			name:         "Context as object (inline)",
			input:        []byte(`{"@context": {"spdx": "https://spdx.org/rdf/3.0.1/"}, "@graph": []}`),
			wantDetected: false,
			wantVersion:  "",
		},
		{
			name:         "SPDX 3.0.2 (unsupported version)",
			input:        []byte(`{"@context": "https://spdx.org/rdf/3.0.22/spdx-context.jsonld", "@graph": []}`),
			wantDetected: false, //only 3.0.x is supported
			wantVersion:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.input)
			spec, format, version, err := detectSbomFormat(r)

			if !tt.wantDetected {
				// Should either error or detect as unknown
				if err == nil {
					assert.Equal(t, SBOMSpecUnknown, spec)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, SBOMSpecSPDX, spec)
			assert.Equal(t, FileFormatJSON, format)
			assert.Equal(t, FormatVersion(tt.wantVersion), version)
		})
	}
}
