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

// Document header and both packages complete.
var cdxDocAndPkgsComplete = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {"timestamp": "2026-08-17T00:00:00Z"},
  "components": [
    {"type": "library", "bom-ref": "a", "name": "lib-a", "version": "1.0"},
    {"type": "library", "bom-ref": "b", "name": "lib-b", "version": "1.0"}
  ]
}
`)

// One of two packages is missing a required field.
var cdxDocOKPkgsPartial = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {"timestamp": "2026-08-17T00:00:00Z"},
  "components": [
    {"type": "library", "bom-ref": "a", "name": "lib-a", "version": "1.0"},
    {"type": "library", "bom-ref": "b", "version": "1.0"}
  ]
}
`)

// Valid header, no components at all.
var cdxDocOKNoComponents = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {"timestamp": "2026-08-17T00:00:00Z"},
  "components": []
}
`)

// Characterization tests. These pin the blended doc+package formula, including
// its quirks, so the scoring cannot drift unnoticed.
func TestSbomWithRequiredFieldCheck(t *testing.T) {
	ctx := context.Background()

	testcases := []struct {
		name      string
		doc       []byte
		wantScore float64
		wantDesc  string
	}{
		{
			name:      "doc and packages complete",
			doc:       cdxDocAndPkgsComplete,
			wantScore: 10.0,
			wantDesc:  "Doc Fields:true Pkg Fields:true",
		},
		{
			// (10 + 10*1/2) / 2
			name:      "doc complete, one of two packages complete",
			doc:       cdxDocOKPkgsPartial,
			wantScore: 7.5,
			wantDesc:  "Doc Fields:true Pkg Fields:false",
		},
		{
			// Known wart: no packages to check, yet the package half scores 0
			// and drags the result to 5.0 instead of reporting N/A the way
			// every sibling component check does.
			name:      "doc complete, zero components",
			doc:       cdxDocOKNoComponents,
			wantScore: 5.0,
			wantDesc:  "Doc Fields:true Pkg Fields:false",
		},
	}

	for _, test := range testcases {
		t.Run(test.name, func(t *testing.T) {
			doc, err := sbom.NewSBOMDocumentFromBytes(ctx, test.doc, sbom.Signature{})
			require.NoError(t, err)

			c := &check{Category: string(semantic), Key: "sbom_required_fields"}
			got := sbomWithRequiredFieldCheck(doc, c)

			assert.InDelta(t, test.wantScore, got.Score(), 1e-9)
			assert.Equal(t, test.wantDesc, got.Descr())
		})
	}
}
