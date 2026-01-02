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
	"context"
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
