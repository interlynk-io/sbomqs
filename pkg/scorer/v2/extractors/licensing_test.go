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

package extractors

import (
	"strings"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
)

type licSpdxMiniComp struct {
	id        string
	name      string
	version   string
	concluded string
	declared  string
}

type licCdx14MiniComp struct {
	id, name, version string
	licenseIDs        []string // e.g., "MIT", "Apache-2.0"
	expressions       []string // e.g., "MIT OR Apache-2.0"
}

// CDX 1.6: every license entry is either {license:{id}} or {expression}, plus acknowledgement.
type cdx16LicItem struct {
	licenseID       string // { "license": { "id": "MIT" } }
	expression      string // { "expression": "MIT OR Apache-2.0" }
	acknowledgement string // must be "declared" or "concluded"
}

type licCdx16MiniComp struct {
	id, name, version string
	items             []cdx16LicItem
}

func makeCDX16DocForLicensing(comps []licCdx16MiniComp, bomDataLicense string) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "1.6"
	s.SpecType = "cyclonedx"
	s.Format = "json"
	s.URI = "urn:uuid:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	if bomDataLicense != "" {
		if dl := licenses.LookupExpression(bomDataLicense, nil); len(dl) > 0 {
			s.Licenses = append(s.Licenses, dl...)
		}
	}

	var cs []sbom.GetComponent
	for _, m := range comps {
		c := sbom.NewComponent()
		c.ID, c.Name, c.Version = m.id, m.name, m.version

		var concluded, declared []licenses.License
		for _, it := range m.items {
			// resolve token from either shape
			var tok string
			if it.licenseID != "" {
				tok = it.licenseID
			} else if it.expression != "" {
				tok = it.expression
			} else {
				continue
			}
			// normalize/expand via your license DB
			ls := licenses.LookupExpression(tok, nil)
			if len(ls) == 0 {
				continue
			}

			switch strings.ToLower(strings.TrimSpace(it.acknowledgement)) {
			case "declared":
				declared = append(declared, ls...)
			case "concluded":
				concluded = append(concluded, ls...)
			default:
				// If an invalid value sneaks in, treat as concluded for presence checks,
				// or you can skip it—your call. Concluded keeps behavior predictable.
				concluded = append(concluded, ls...)
			}
		}

		// Map onto your wrapper fields used by extractors
		c.ConcludedLicense = concluded // CDX 1.6 items with ack=concluded
		c.Licenses = concluded         // unified “effective” licenses list
		c.DeclaredLicense = declared   // CDX 1.6 items with ack=declared

		cs = append(cs, c)
	}

	return sbom.CdxDoc{CdxSpec: s, Comps: cs}
}

// CDX 1.4: licenses[] without acknowledgement
func makeCDX14DocForLicensing(comps []licCdx14MiniComp, bomLicense string) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "1.4"
	s.SpecType = "cyclonedx"
	s.Format = "json"
	s.URI = "urn:uuid:11111111-2222-3333-4444-555555555555"

	if bomLicense != "" {
		if dl := licenses.LookupExpression(bomLicense, nil); len(dl) > 0 {
			s.Licenses = append(s.Licenses, dl...)
		}
	}

	var cs []sbom.GetComponent
	for _, m := range comps {
		c := sbom.NewComponent()
		c.ID = m.id
		c.Name = m.name
		c.Version = m.version

		var lics []licenses.License
		for _, id := range m.licenseIDs {
			if ls := licenses.LookupExpression(id, nil); len(ls) > 0 {
				lics = append(lics, ls...)
			}
		}

		for _, ex := range m.expressions {
			if ls := licenses.LookupExpression(ex, nil); len(ls) > 0 {
				lics = append(lics, ls...)
			}
		}

		c.ConcludedLicense = lics
		c.Licenses = lics

		cs = append(cs, c)
	}

	return sbom.CdxDoc{CdxSpec: s, Comps: cs}
}

// Build an SPDX doc with components and the given spec-level data licenses.
func makeSPDXDocForLicensing(comps []licSpdxMiniComp, dataLicenses string) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.Spdxid = "DOCUMENT"
	s.Namespace = "https://example.com/ns"

	if dataLicenses != "" {
		lics := licenses.LookupExpression(dataLicenses, nil)
		if len(lics) > 0 {
			s.Licenses = append(s.Licenses, lics...)
		}
	}

	var cs []sbom.GetComponent
	for _, m := range comps {
		c := sbom.NewComponent()
		c.ID = m.id
		c.Name = m.name
		c.Version = m.version

		var conLics []licenses.License

		if m.concluded != "" {
			lics := licenses.LookupExpression(m.concluded, nil)
			if len(lics) > 0 {
				conLics = append(conLics, lics...)
			}
		}
		c.ConcludedLicense = conLics
		c.Licenses = conLics

		var decLics []licenses.License
		// inject licenses
		if m.declared != "" {
			lics := licenses.LookupExpression(m.declared, nil)
			if len(lics) > 0 {
				decLics = append(decLics, lics...)
			}
		}
		c.DeclaredLicense = decLics

		cs = append(cs, c)
	}

	return sbom.SpdxDoc{
		SpdxSpec: s,
		Comps:    cs,
	}
}

func Test_CompWithLicenses(t *testing.T) {
	t.Run("SpdxWithNoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("SpdxAllHaveConcludedLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "mit"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "Apache-2.0"},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxComponentsWithOneNoassertion", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "LicenseRef-MyCustom"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "NOASSERTION"},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxComponentsBothInvalidLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "NONE"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "NOASSERTION"},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX Testing:1.4
	t.Run("Cdx14NoComponents", func(t *testing.T) {
		doc := makeCDX14DocForLicensing(nil, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("Cdx14LicenseWithIdAndExpression", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", licenseIDs: []string{"MIT"}},
			{id: "b", name: "b", version: "2", expressions: []string{"Apache-2.0 OR BSD-3-Clause"}},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
	})

	t.Run("Cdx14ValidIdAndInvalidExpression", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", licenseIDs: []string{"MIT"}},
			{id: "b", name: "b", version: "2", expressions: []string{"NOASSERTION"}},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)
		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
	})

	t.Run("Cdx14WithBothInvalidExpression", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", licenseIDs: []string{"NONE"}},
			{id: "b", name: "b", version: "2", expressions: []string{"NOASSERTION"}},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
	})

	// CDX testing: 1.6
	t.Run("Cdx16ValidIdAndInvalidExpressionWithAck", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "MIT", acknowledgement: "concluded"},
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{expression: "NOASSERTION", acknowledgement: "declared"},
				},
			},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)
		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("Cdx16WithBothDeclaredLicense", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "mit", acknowledgement: "declared"},
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{expression: "apache-2.0", acknowledgement: "declared"},
				},
			},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("Cdx16DeclaredAndConcludedOnSameComponent", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "MIT", acknowledgement: "concluded"},
					{licenseID: "BSD-3-Clause", acknowledgement: "declared"},
				},
			},
		}, "CC0-1.0")

		gotConc := CompWithLicenses(doc)

		assert.InDelta(t, 10.0, gotConc.Score, 1e-9)
		assert.Equal(t, "complete", gotConc.Desc)

		gotDecl := CompWithDeclaredLicenses(doc)
		assert.InDelta(t, 10.0, gotDecl.Score, 1e-9)
		assert.Equal(t, "complete", gotDecl.Desc)
	})
}

func Test_CompWithValidLicenses(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("ValidLicensesMixedOfSpdxAndCustom", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "MIT"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "LicenseRef-MyCustom"},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithALLInvalidLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "Custom-foo"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "Custom-bar"},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		// 2/3 → 6.666...
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithALLCustomValidLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "LicenseRef-foo"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "LicenseRef-bar"},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithALLBadLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "NOASSERTION"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "NONE"},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX:1.4
	t.Run("LicenseWithValidIDAndExpression", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", expressions: []string{"MIT OR LicenseRef-Custom"}},
			{id: "b", name: "b", version: "2", licenseIDs: []string{"BSD-3-Clause"}},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
	})

	// CDX:1.6
	t.Run("WithMixOfInvalidAndValidLicenses", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{expression: "MIT OR LicenseRef-Custom", acknowledgement: "concluded"}, // valid (SPDX + LicenseRef-*)
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{licenseID: "Custom-NotRef", acknowledgement: "concluded"}, // invalid (fails areLicensesValid)
				},
			},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func Test_CompWithDeclaredLicenses(t *testing.T) {
	t.Run("SpdxWithNoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithDeclaredLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("SpdxWithValidAndEmptyLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", declared: "Apache-2.0"},
			{id: "SPDXRef-B", name: "b", version: "2", declared: ""},
		}, "CC0-1.0")

		got := CompWithDeclaredLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithNOASSERTIONAndEmptyLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", declared: "NOASSERTION"},
			{id: "SPDXRef-B", name: "b", version: "2", declared: ""},
		}, "CC0-1.0")

		got := CompWithDeclaredLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
	})

	// CDX:1.4
	t.Run("CDX14WithALLConcludedLicenses", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", expressions: []string{"MIT OR LicenseRef-Custom"}},
			{id: "b", name: "b", version: "2", licenseIDs: []string{"BSD-3-Clause"}},
		}, "CC0-1.0")

		got := CompWithDeclaredLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
	})

	// CDX:1.6
	t.Run("CDX16WithALLDeclaredLicenses", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "Apache-2.0", acknowledgement: "declared"},
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{expression: "MIT OR BSD-3-Clause", acknowledgement: "declared"},
				},
			},
		}, "CC-BY-4.0")

		got := CompWithDeclaredLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("CDX16WithALLConcludedLicenses", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "Apache-2.0", acknowledgement: "concluded"},
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{expression: "MIT OR BSD-3-Clause", acknowledgement: "concluded"},
				},
			},
		}, "CC-BY-4.0")

		got := CompWithDeclaredLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func Test_SBOMDataLicense(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "")

		got := SBOMDataLicense(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.False(t, got.Ignore)
		assert.Equal(t, "add data license", got.Desc)
	})

	t.Run("valid SPDX data license -> 10", func(t *testing.T) {
		dl := "CC-BY-4.0"
		doc := makeSPDXDocForLicensing(nil, dl)

		got := SBOMDataLicense(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("invalid custom (not LicenseRef-) -> 0", func(t *testing.T) {
		dl := "invalid-license"
		doc := makeSPDXDocForLicensing(nil, dl)

		got := SBOMDataLicense(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "fix data license", got.Desc)
	})

	t.Run("non-recommended doc SPDX data license -> 10", func(t *testing.T) {
		dl := "Apache-2.0"
		doc := makeSPDXDocForLicensing(nil, dl)

		got := SBOMDataLicense(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func Test_CompWithDeprecatedLicenses(t *testing.T) {
	t.Run("SpdxWithNoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("SpdxWithOneDeprecatedLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "AGPL-1.0"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "MIT"},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "fix 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithTwoDeprecatedLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "GPL-1.0-only"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "AGPL-1.0"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "BSD-2-Clause-FreeBSD"},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		// 2 deprecated out of 3, so 1 WITHOUT deprecated → 1/3 = 3.33
		assert.InDelta(t, 10.0*(1.0/3.0), got.Score, 1e-9)
		assert.Equal(t, "fix 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithBothValidLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "Apache-2.0"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "LicenseRef-MyCustom"},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		// 0 deprecated, so 2 WITHOUT deprecated → 2/2 = 10.0
		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithCustomAndNOASSERTIONLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "Custom-license"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "NOASSERTION"},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		// 0 deprecated, so 2 WITHOUT deprecated → 2/2 = 10.0
		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX:1.6
	t.Run("LicenseWithValidIDAndInvalidExpression", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "AGPL-1.0", acknowledgement: "concluded"}, // deprecated
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{licenseID: "BSD-3-Clause", acknowledgement: "declared"},
				},
			},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "fix 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func Test_CompWithRestrictiveLicenses(t *testing.T) {
	t.Run("NoComponentsNA", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithRestrictiveLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("SpdxAllRestrictive", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "GPL-2.0-only"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "GPL-3.0-only"},
		}, "CC0-1.0")

		got := CompWithRestrictiveLicenses(doc)

		// 2 restrictive out of 2, so 0 WITHOUT restrictive → 0/2 = 0.0
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "review 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxNoneRestrictive", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "Apache-2.0"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "LicenseRef-custom"},
			{id: "SPDXRef-C", name: "c", version: "3", concluded: "custom-license"},
		}, "CC0-1.0")

		got := CompWithRestrictiveLicenses(doc)

		// 0 restrictive, so 3 WITHOUT restrictive → 3/3 = 10.0
		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxPartialRestrictive", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "GPL-2.0-only"},   // restrictive
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "MIT"},            // not
			{id: "SPDXRef-C", name: "c", version: "3", concluded: "LicenseRef-foo"}, // not
		}, "CC0-1.0")

		got := CompWithRestrictiveLicenses(doc)

		// 1 restrictive out of 3, so 2 WITHOUT restrictive → 2/3 = 6.67
		assert.InDelta(t, 10.0*(2.0/3.0), got.Score, 1e-9)
		assert.Equal(t, "review 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX 1.6 — only concluded counts; declared should not
	t.Run("Cdx16ConcludedRestrictiveDeclaredNonRestrictive", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "GPL-3.0-only", acknowledgement: "concluded"}, // restrictive
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{licenseID: "GPL-2.0-only", acknowledgement: "declared"}, // declared → should NOT count
				},
			},
		}, "CC0-1.0")
		got := CompWithRestrictiveLicenses(doc)
		// 1 restrictive out of 2, so 1 WITHOUT restrictive → 1/2 = 5.0
		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "review 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// NOASSERTION/NONE not restrictive
	t.Run("Cdx16NoAssertionNotRestrictive", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{expression: "NOASSERTION", acknowledgement: "concluded"},
				},
			},
			{
				id: "b", name: "b", version: "2",
				items: []cdx16LicItem{
					{licenseID: "NONE", acknowledgement: "concluded"},
				},
			},
		}, "CC0-1.0")
		got := CompWithRestrictiveLicenses(doc)
		// 0 restrictive, so 2 WITHOUT restrictive → 2/2 = 10.0
		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// Custom LicenseRef-* should not be restrictive
	t.Run("CustomLicenseRefNotRestrictive", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "LicenseRef-MyCustom"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "MIT"},
		}, "CC0-1.0")
		got := CompWithRestrictiveLicenses(doc)
		// 0 restrictive, so 2 WITHOUT restrictive → 2/2 = 10.0
		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}
