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

	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
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
	t.Run("no components -> N/A", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("all have concluded licenses -> 10.0", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "MIT"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "Apache-2.0"},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "2/2 have licenses", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("partial presence (NOASSERTION treated as absent)", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "BSD-3-Clause"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "NOASSERTION"},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 have licenses", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX Testing:1.4
	t.Run("no components -> N/A", func(t *testing.T) {
		doc := makeCDX14DocForLicensing(nil, "CC0-1.0")

		got := CompWithLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("LicenseWithBothExpressionAndID", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", licenseIDs: []string{"MIT"}},
			{id: "b", name: "b", version: "2", expressions: []string{"Apache-2.0 OR BSD-3-Clause"}},
		}, "Apache-2.0")

		got := CompWithLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "2/2 have licenses", got.Desc)
	})

	t.Run("LicenseWithValidIDAndExpression", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", expressions: []string{"MIT OR LicenseRef-Custom"}},
			{id: "b", name: "b", version: "2", licenseIDs: []string{"BSD-3-Clause"}},
		}, "MIT")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "2/2 have valid SPDX licenses", got.Desc)
	})

	t.Run("LicenseWithValidIDAndInvalidExpression", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", licenseIDs: []string{"MIT"}},
			{id: "b", name: "b", version: "2", expressions: []string{"NOASSERTION"}},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)
		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 have licenses", got.Desc)
	})

	t.Run("LicenseWithInvalidIDAndInvalidExpression", func(t *testing.T) {
		doc := makeCDX14DocForLicensing([]licCdx14MiniComp{
			{id: "a", name: "a", version: "1", licenseIDs: []string{"NONE"}},
			{id: "b", name: "b", version: "2", expressions: []string{"NOASSERTION"}},
		}, "CC0-1.0")

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "0/2 have licenses", got.Desc)
	})

	// CDX testing: 1.6

	t.Run("LicenseWithValidIDAndInvalidExpression", func(t *testing.T) {
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
		}, "MIT")

		got := CompWithLicenses(doc)
		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 have licenses", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("CDX16 same component has declared and concluded", func(t *testing.T) {
		doc := makeCDX16DocForLicensing([]licCdx16MiniComp{
			{
				id: "a", name: "a", version: "1",
				items: []cdx16LicItem{
					{licenseID: "MIT", acknowledgement: "concluded"},
					{licenseID: "BSD-3-Clause", acknowledgement: "declared"},
				},
			},
		}, "MIT")

		gotConc := CompWithLicenses(doc)
		assert.InDelta(t, 10.0, gotConc.Score, 1e-9)
		assert.Equal(t, "1/1 have licenses", gotConc.Desc)

		gotDecl := CompWithDeclaredLicenses(doc)
		assert.InDelta(t, 10.0, gotDecl.Score, 1e-9)
		assert.Equal(t, "1/1 have declared", gotDecl.Desc)
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
		assert.Equal(t, "2/2 have valid SPDX licenses", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLCustomInvalidLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "Custom-foo"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "Custom-bar"},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		// 2/3 → 6.666...
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "0/2 have valid SPDX licenses", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLCustomValidLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "LicenseRef-foo"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "LicenseRef-bar"},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "2/2 have valid SPDX licenses", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLInvalidLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "NOASSERTION"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "NONE"},
		}, "CC0-1.0")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "0/2 have valid SPDX licenses", got.Desc)
		assert.False(t, got.Ignore)
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
		}, "MIT")

		got := CompWithValidLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 have valid SPDX licenses", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func Test_CompWithDeclaredLicenses(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithDeclaredLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("MixedOfValidAndEmptyLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", declared: "Apache-2.0"},
			{id: "SPDXRef-B", name: "b", version: "2", declared: ""},
		}, "CC0-1.0")

		got := CompWithDeclaredLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 have declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("MixedOfInvalidAndEmptyLicenses", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", declared: "NOASSERTION"},
			{id: "SPDXRef-B", name: "b", version: "2", declared: ""},
		}, "CC0-1.0")

		got := CompWithDeclaredLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "0/2 have declared", got.Desc)
	})

	// CDX:1.6
	t.Run("BothDeclaredLicenses", func(t *testing.T) {
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
		assert.Equal(t, "2/2 have declared", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func Test_SBOMDataLicense(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "")

		got := SBOMDataLicense(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.False(t, got.Ignore)
		assert.Equal(t, "no data license", got.Desc)
	})

	t.Run("valid SPDX data license -> 10", func(t *testing.T) {
		dl := "CC-BY-4.0"
		doc := makeSPDXDocForLicensing(nil, dl)

		got := SBOMDataLicense(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Contains(t, got.Desc, "CC-BY-4.0")
		assert.False(t, got.Ignore)
	})

	t.Run("invalid custom (not LicenseRef-) -> 0", func(t *testing.T) {
		dl := "invalid-license"
		doc := makeSPDXDocForLicensing(nil, dl)

		got := SBOMDataLicense(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "invalid data license", got.Desc)
	})

	t.Run("non-recommended doc SPDX data license -> 10", func(t *testing.T) {
		dl := "Apache-2.0"
		doc := makeSPDXDocForLicensing(nil, dl)

		got := SBOMDataLicense(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Contains(t, got.Desc, "Apache-2.0")
		assert.False(t, got.Ignore)
	})
}

func Test_CompWithDeprecatedLicenses(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("WithOneDeprecatedLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "AGPL-1.0"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "MIT"},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1 deprecated", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLDeprecatedLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "GPL-1.0-only"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "AGPL-1.0"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "BSD-2-Clause-FreeBSD"},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		assert.InDelta(t, 10.0*(2.0/3.0), got.Score, 1e-9)
		assert.Equal(t, "2 deprecated", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("NoDeprecatedLicense", func(t *testing.T) {
		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
			{id: "SPDXRef-A", name: "a", version: "1", concluded: "Apache-2.0"},
			{id: "SPDXRef-B", name: "b", version: "2", concluded: "MIT"},
		}, "CC0-1.0")

		got := CompWithDeprecatedLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "0 deprecated", got.Desc)
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
		assert.Equal(t, "1 deprecated", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// func Test_CompWithNoRestrictiveLicenses(t *testing.T) {
// 	t.Run("NoComponents", func(t *testing.T) {
// 		doc := makeSPDXDocForLicensing(nil, "CC0-1.0")

// 		got := CompWithRestrictiveLicenses(doc)

// 		assert.Equal(t, 0.0, got.Score)
// 		assert.True(t, got.Ignore)
// 		assert.Equal(t, "N/A (no components)", got.Desc)
// 	})

// 	t.Run("BothRestrictiveLicense", func(t *testing.T) {
// 		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
// 			{id: "SPDXRef-A", name: "a", version: "1", concluded: "GPL-2.0-only"},
// 			{id: "SPDXRef-B", name: "b", version: "2", concluded: "GPL-3.0-only"},
// 		}, "CC0-1.0")

// 		got := CompWithRestrictiveLicenses(doc)

// 		assert.InDelta(t, 10.0, got.Score, 1e-9)
// 		assert.Equal(t, "2 restrictive", got.Desc)
// 		assert.False(t, got.Ignore)
// 	})

// 	t.Run("ZerorestrictiveLicense", func(t *testing.T) {
// 		doc := makeSPDXDocForLicensing([]licSpdxMiniComp{
// 			{id: "SPDXRef-A", name: "a", version: "1", concluded: "Apache-2.0"},
// 			{id: "SPDXRef-B", name: "b", version: "2", concluded: "MIT"},
// 		}, "CC0-1.0")

// 		got := CompWithRestrictiveLicenses(doc)

// 		assert.InDelta(t, 0.0, got.Score, 1e-9) // only BSD comp is “without restrictive”
// 		assert.Equal(t, "0 restrictive", got.Desc)
// 		assert.False(t, got.Ignore)
// 	})
// }
