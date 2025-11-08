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

package profiles

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/stretchr/testify/assert"
)

func spdxDocSpec(ver, fileFmt, spec string) *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = ver
	s.SpecType = spec
	s.Format = fileFmt
	s.Spdxid = "DOCUMENT"
	s.Namespace = "https://example.com/ns"
	return s
}

func cdxDocSpec(ver, fileFmt, spec string) *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = ver
	s.SpecType = spec
	s.Format = fileFmt
	s.URI = "urn:uuid:11111111-2222-3333-4444-555555555555"
	return s
}

func Test_SBOMSpec(t *testing.T) {
	t.Run("SupportedSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "spdx")}

		got := SBOMSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present spdx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SupportedSPDXUpperCase", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "SPDX")}

		got := SBOMSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present spdx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("UnsupportedSpec", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "something-else")}

		got := SBOMSpec(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Contains(t, got.Desc, "unsupported spec")
	})

	t.Run("UnsupportedSpec", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-4.3", "yaml", "something-else")}

		got := SBOMSpec(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Contains(t, got.Desc, "unsupported spec")
	})
}

func Test_SBOMSpecVersion(t *testing.T) {
	t.Run("SupportedSPDXVersion", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "spdx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present SPDX-2.3", got.Desc)
	})

	t.Run("UnSupportedSPDXVersion", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-100.3", "json", "spdx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported spec version: SPDX-100.3 (spec spdx)", got.Desc)
	})

	t.Run("UnsupportedCDXVersion", func(t *testing.T) {
		doc := sbom.CdxDoc{CdxSpec: cdxDocSpec("9.9", "json", "cyclonedx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported spec version: 9.9 (spec cyclonedx)", got.Desc)
	})
}

func Test_SBOMFileFormat(t *testing.T) {
	t.Run("SupportedFormatForSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "spdx")}

		got := SBOMAutomationSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present json", got.Desc)
	})

	t.Run("UnsupportedFormatForSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "pdf", "spdx")}

		got := SBOMAutomationSpec(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported file format: pdf (spec spdx)", got.Desc)
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		doc := sbom.CdxDoc{CdxSpec: cdxDocSpec("1.4", "ppl", "cyclonedx")}

		got := SBOMAutomationSpec(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported file format: ppl (spec cyclonedx)", got.Desc)
	})
}

func cdxDocLifecycle(lifecycle string) sbom.CdxDoc {
	s := sbom.NewSpec()
	s.Version = "1.6"
	s.SpecType = "cyclonedx"
	s.Format = "json"

	return sbom.CdxDoc{
		CdxSpec:   s,
		Lifecycle: []string{lifecycle},
	}
}

func spdxDocLifecycle() sbom.SpdxDoc {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"

	return sbom.SpdxDoc{
		SpdxSpec: s,
	}
}

func Test_SBOMLifeCycle(t *testing.T) {
	t.Run("SPDX → N/A", func(t *testing.T) {
		doc := spdxDocLifecycle()
		got := SBOMLifeCycle(doc)
		assert.True(t, got.Ignore)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "N/A (SPDX)", got.Desc)
	})

	t.Run("CDX lifecycles present → 10", func(t *testing.T) {
		doc := cdxDocLifecycle("build")
		got := SBOMLifeCycle(doc)
		assert.False(t, got.Ignore)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present build", got.Desc)
	})

	t.Run("CDX lifecycles present → 10", func(t *testing.T) {
		doc := cdxDocLifecycle("runtime")
		got := SBOMLifeCycle(doc)
		assert.False(t, got.Ignore)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present runtime", got.Desc)
	})

	t.Run("CDX lifecycles missing → 0", func(t *testing.T) {
		doc := cdxDocLifecycle("")
		got := SBOMLifeCycle(doc)
		assert.False(t, got.Ignore)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing lifecycle", got.Desc)
	})
}

func cdxDocForNamespace(ns string) sbom.CdxDoc {
	s := sbom.NewSpec()
	s.Version = "1.6"
	s.SpecType = "cyclonedx"
	s.Format = "json"
	s.URI = ns

	return sbom.CdxDoc{
		CdxSpec: s,
	}
}

func spdxDocForNamespace(ns string) sbom.SpdxDoc {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.URI = ns

	return sbom.SpdxDoc{
		SpdxSpec: s,
	}
}

func Test_SBOMNamespace(t *testing.T) {
	t.Run("SPDX namespace present → 10", func(t *testing.T) {
		doc := spdxDocForNamespace("https://example.com/ns")
		got := SBOMNamespace(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present namespace", got.Desc)
	})

	t.Run("SPDX namespace missing → 0", func(t *testing.T) {
		doc := spdxDocForNamespace("")
		got := SBOMNamespace(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing namespace", got.Desc)
	})

	t.Run("CDX uri present → 10", func(t *testing.T) {
		doc := cdxDocForNamespace("urn:uuid:123e4567-e89b-12d3-a456-426614174000")
		got := SBOMNamespace(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present namespace", got.Desc)
	})

	t.Run("CDX uri missing → 0", func(t *testing.T) {
		doc := cdxDocForNamespace("")
		got := SBOMNamespace(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing namespace", got.Desc)
	})
}

type author struct {
	Name  string
	Email string
	URL   string
	Type  string
}

func cdxDocForAuthor(authors []author) sbom.CdxDoc {
	s := sbom.NewSpec()
	s.Version = "1.6"
	s.SpecType = "cyclonedx"
	s.Format = "json"

	var aths []sbom.GetAuthor

	for _, a := range authors {
		aths = append(aths, sbom.Author{Name: a.Name, Email: a.Email, AuthorType: a.Type})
	}
	return sbom.CdxDoc{
		CdxSpec:    s,
		CdxAuthors: aths,
	}
}

func spdxDocForAuthor(authors []author) sbom.SpdxDoc {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"

	var aths []sbom.GetAuthor

	for _, a := range authors {
		aths = append(aths, sbom.Author{Name: a.Name, Email: a.Email, AuthorType: a.Type})
	}
	return sbom.SpdxDoc{
		SpdxSpec: s,
		Auths:    aths,
	}
}

func Test_SBOMAuthors(t *testing.T) {
	// SPDX Doc with 0 authors
	t.Run("SPDX zero authors → 0", func(t *testing.T) {
		doc := spdxDocForAuthor(nil)
		got := SBOMAuthors(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing authors", got.Desc)
	})

	// SPDX Doc with 1 author of type person
	t.Run("SPDX one authors → 10", func(t *testing.T) {
		doc := spdxDocForAuthor([]author{
			{
				Name:  "foo",
				Email: "foo@gmail.com",
				Type:  "person",
			},
		},
		)
		got := SBOMAuthors(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present 1 legal authors", got.Desc)
	})

	// SPDX Doc with 2 authors, one of type person and another of organization
	t.Run("SPDX some authors → 10", func(t *testing.T) {
		doc := spdxDocForAuthor([]author{
			{
				Name:  "foo",
				Email: "foo@gmail.com",
				Type:  "person",
			},
			{
				Name:  "bar",
				Email: "bar@gmail.com",
				Type:  "organization",
			},
		},
		)
		got := SBOMAuthors(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, got.Desc, "present 2 legal authors")
	})
}

func commonSpdxSpec() *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"

	return s
}

func spdxDocForPurl(purls []string) sbom.SpdxDoc {
	s := commonSpdxSpec()

	var cs []sbom.GetComponent
	for _, p := range purls {
		c := sbom.NewComponent()
		c.Name = "abc"
		c.Version = "v1.1"
		c.Purls = append(c.Purls, purl.PURL(p))

		cs = append(cs, c)
	}

	return sbom.SpdxDoc{
		SpdxSpec: s,
		Comps:    cs,
	}
}

func commonCdxSpec() *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = "1.4"
	s.SpecType = "cyclonedx"
	s.Format = "json"
	return s
}

func cdxDocForPurl(purls []string) sbom.CdxDoc {
	s := commonCdxSpec()

	var cs []sbom.GetComponent
	for _, p := range purls {
		c := sbom.NewComponent()
		c.Name = "abc"
		c.Version = "v1.1"
		c.Purls = append(c.Purls, purl.PURL(p))

		cs = append(cs, c)
	}

	return sbom.CdxDoc{
		CdxSpec: s,
		Comps:   cs,
	}
}

func Test_CompWithPURL(t *testing.T) {
	t.Run("SpdxWithNoComponents", func(t *testing.T) {
		doc := spdxDocForPurl(nil)

		got := CompUniqID(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.False(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})

	t.Run("spdxWithValidPURLs", func(t *testing.T) {
		doc := spdxDocForPurl([]string{
			"pkg:npm/lodash@4.17.21",
			"pkg:maven/org.apache.commons/commons-lang3@3.12.0",
		})
		got := CompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "2/2 have unique ID", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("apdxWithPartialValidPURLs", func(t *testing.T) {
		doc := spdxDocForPurl([]string{
			"pkg:golang/github.com/pkg/errors@0.9.1",
			"not-a-purl",
			"",
		})

		got := CompUniqID(doc)
		// 1/3 = 3.333…
		assert.InDelta(t, 10.0*(1.0/3.0), got.Score, 1e-9)
		assert.Equal(t, "1/3 have unique ID", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SpdxWithNoValidPURLs", func(t *testing.T) {
		doc := spdxDocForPurl([]string{
			"pkg",
			"pkg:/",
			"notpkg:npm/foo",
		})

		got := CompUniqID(doc)
		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "0/3 have unique ID", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPURLWithQualifiersAndSubpath", func(t *testing.T) {
		doc := spdxDocForPurl([]string{
			"pkg:maven/org.apache.commons/commons-lang3@3.12.0?classifier=sources#src/main",
		})

		got := CompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.False(t, got.Ignore)
		assert.Equal(t, "1/1 have unique ID", got.Desc)
	})

	// CDX:1.4
	t.Run("cDXWithALLValidPURLs", func(t *testing.T) {
		doc := cdxDocForPurl([]string{
			"pkg:npm/lodash@4.17.21",
			"pkg:maven/org.apache.commons/commons-lang3@3.12.0",
		})
		got := CompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "2/2 have unique ID", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cDXWithPartialValidPURLs", func(t *testing.T) {
		doc := cdxDocForPurl([]string{
			"pkg:golang/github.com/pkg/errors@0.9.1",
			"not-a-purl",
			"",
		})

		got := CompUniqID(doc)

		assert.InDelta(t, 10.0*(1.0/3.0), got.Score, 1e-9)
		assert.Equal(t, "1/3 have unique ID", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cDXWithNoValidPURLs", func(t *testing.T) {
		doc := cdxDocForPurl([]string{
			"notpkg:npm/foo",
			"",
		})

		got := CompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "0/2 have unique ID", got.Desc)
		assert.False(t, got.Ignore)
	})
}
