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

package scorer

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Components carry bom-refs but no purl and no cpe. This is the case the old
// implementation scored 10.0 on, because it counted bom-refs.
var cdxCompsWithLocalIDsOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {"type": "library", "bom-ref": "a", "name": "lib-a", "version": "1.0"},
    {"type": "library", "bom-ref": "b", "name": "lib-b", "version": "1.0"}
  ]
}
`)

var cdxCompsWithPurl = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {"type": "library", "bom-ref": "a", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"},
    {"type": "library", "bom-ref": "b", "name": "lib-b", "version": "1.0", "purl": "pkg:npm/lib-b@1.0"}
  ]
}
`)

var cdxCompsWithCpeOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {"type": "library", "bom-ref": "a", "name": "lib-a", "version": "1.0", "cpe": "cpe:2.3:a:vendor:lib-a:1.0:*:*:*:*:*:*:*"},
    {"type": "library", "bom-ref": "b", "name": "lib-b", "version": "1.0", "cpe": "cpe:2.3:a:vendor:lib-b:1.0:*:*:*:*:*:*:*"}
  ]
}
`)

// One of four components carries an identifier.
var cdxCompsWithMixedIDs = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {"type": "library", "bom-ref": "a", "name": "lib-a", "version": "1.0", "purl": "pkg:npm/lib-a@1.0"},
    {"type": "library", "bom-ref": "b", "name": "lib-b", "version": "1.0"},
    {"type": "library", "bom-ref": "c", "name": "lib-c", "version": "1.0"},
    {"type": "library", "bom-ref": "d", "name": "lib-d", "version": "1.0"}
  ]
}
`)

var spdxCompsWithPurl = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {"created": "2026-08-17T00:00:00Z", "creators": ["Tool: test-1.0"]},
  "packages": [
    {
      "SPDXID": "SPDXRef-a", "name": "lib-a", "versionInfo": "1.0",
      "downloadLocation": "NOASSERTION",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lib-a@1.0"}
      ]
    }
  ]
}
`)

var spdxCompsWithLocalIDsOnly = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {"created": "2026-08-17T00:00:00Z", "creators": ["Tool: test-1.0"]},
  "packages": [
    {"SPDXID": "SPDXRef-a", "name": "lib-a", "versionInfo": "1.0", "downloadLocation": "NOASSERTION"}
  ]
}
`)

// comp_with_uniq_ids implements the NTIA minimum element "Other Unique
// Identifiers": at least one lookup identifier (PURL, CPE, SWID) per component.
// A bom-ref or SPDXID is a document-local handle and must not satisfy it.
func TestCompWithUniqIDCheck(t *testing.T) {
	ctx := context.Background()

	testcases := []struct {
		name      string
		doc       []byte
		wantScore float64
		wantDesc  string
	}{
		{
			name:      "cdx purl on every component",
			doc:       cdxCompsWithPurl,
			wantScore: 10.0,
			wantDesc:  "2/2 have unique ID's",
		},
		{
			name:      "cdx cpe on every component",
			doc:       cdxCompsWithCpeOnly,
			wantScore: 10.0,
			wantDesc:  "2/2 have unique ID's",
		},
		{
			// Regression: bom-refs alone previously scored 10.0.
			name:      "cdx bom-ref only, no purl or cpe",
			doc:       cdxCompsWithLocalIDsOnly,
			wantScore: 0.0,
			wantDesc:  "0/2 have unique ID's",
		},
		{
			name:      "cdx one of four has a purl",
			doc:       cdxCompsWithMixedIDs,
			wantScore: 2.5,
			wantDesc:  "1/4 have unique ID's",
		},
		{
			name:      "spdx externalRef purl",
			doc:       spdxCompsWithPurl,
			wantScore: 10.0,
			wantDesc:  "1/1 have unique ID's",
		},
		{
			// Regression: SPDXID alone previously scored 10.0.
			name:      "spdx SPDXID only, no externalRefs",
			doc:       spdxCompsWithLocalIDsOnly,
			wantScore: 0.0,
			wantDesc:  "0/1 have unique ID's",
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			doc, err := sbom.NewSBOMDocumentFromBytes(ctx, test.doc, sbom.Signature{})
			require.NoError(t, err)

			c := &check{Category: string(ntiam), Key: "comp_with_uniq_ids"}
			got := compWithUniqIDCheck(doc, c)

			assert.InDelta(t, test.wantScore, got.Score(), 1e-9)
			assert.Equal(t, test.wantDesc, got.Descr())
			assert.False(t, got.Ignore())
		})
	}
}

func TestCompWithUniqIDCheck_NoComponents(t *testing.T) {
	ctx := context.Background()

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": []
}
`), sbom.Signature{})
	require.NoError(t, err)

	c := &check{Category: string(ntiam), Key: "comp_with_uniq_ids"}
	got := compWithUniqIDCheck(doc, c)

	assert.InDelta(t, 0.0, got.Score(), 1e-9)
	assert.Equal(t, "N/A (no components)", got.Descr())
	assert.True(t, got.Ignore())
}
