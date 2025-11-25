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
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
)

func newSPDXSpec() *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.Spdxid = "DOCUMENT"
	s.SpecType = "spdx"
	s.Format = "json"
	s.Organization = "interlynk"
	s.CreationTimestamp = "2025-01-01T00:00:00Z"
	s.Namespace = "https://example.com/test-namespace"
	return s
}

func comp(name, version, id string) sbom.GetComponent {
	c := sbom.NewComponent()
	c.Name = name
	c.Version = version
	c.ID = id
	return c
}

func spdxDocWithComponents(comps ...sbom.GetComponent) sbom.Document {
	return sbom.SpdxDoc{
		SpdxSpec: newSPDXSpec(),
		Comps:    comps,
	}
}

func TestCompWithName_SomeMissing(t *testing.T) {
	doc := spdxDocWithComponents(
		comp("MainPkg", "1.0.0", "SPDXRef-MainPkg"),
		comp("", "1.4.0", "SPDXRef-EmptyName"),
		comp("  ", "0.1.0", "SPDXRef-Whitespace"),
		comp("Another", "2.0.0", "SPDXRef-Another"),
	)

	got := CompWithName(doc)

	// 2 named out of 4 → 10 * (2/4) = 5.0
	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, got.Desc, "add to 2 components")
	assert.False(t, got.Ignore)
}

func TestCompWithName_NoComponents_NA(t *testing.T) {
	doc := spdxDocWithComponents() // no components

	got := CompWithName(doc)

	assert.Equal(t, 0.0, got.Score)
	assert.True(t, got.Ignore, "no components → N/A (ignored so category renormalizes)")
	assert.Equal(t, got.Desc, "N/A (no components)")
}

type miniComp struct {
	id, name, version string
}

func makeSPDXDoc(components []miniComp) sbom.Document {
	var tools []sbom.GetTool
	tools = append(tools, sbom.Tool{Name: "syft", Version: "v0.95.0"})

	var comps []sbom.GetComponent
	for _, c := range components {
		p := sbom.NewComponent()
		p.ID = c.id
		p.Name = c.name
		p.Version = c.version
		comps = append(comps, p)
	}

	return sbom.SpdxDoc{
		SpdxSpec:  newSPDXSpec(),
		Comps:     comps,
		SpdxTools: tools,
	}
}

func makeCDXDoc(components []miniComp) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "1.6"
	s.SpecType = "cyclonedx"
	s.Format = "json"
	s.Organization = "interlynk"
	s.CreationTimestamp = "2025-01-01T00:00:00Z"
	s.Namespace = "urn:uuid:abcd-1234"
	s.Licenses = append(s.Licenses, licenses.CreateCustomLicense("", "CC0-1.0"))

	var tools []sbom.GetTool
	tools = append(tools, sbom.Tool{Name: "syft", Version: "v0.95.0"})

	var comps []sbom.GetComponent
	for _, c := range components {
		p := sbom.NewComponent()
		// For CDX, ID maps to bom-ref in your wrapper
		p.ID = c.id
		p.Name = c.name
		p.Version = c.version
		comps = append(comps, p)
	}

	return sbom.CdxDoc{
		CdxSpec:  s,
		Comps:    comps,
		CdxTools: tools,
	}
}

func TestCompWithVersion_SPdx(t *testing.T) {
	t.Run("all have versions → 10.0", func(t *testing.T) {
		doc := makeSPDXDoc([]miniComp{
			{id: "SPDXRef-A", name: "a", version: "1.0.0"},
			{id: "SPDXRef-B", name: "b", version: "2.0.0"},
		})

		got := CompWithVersion(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("partial versions → 5.0", func(t *testing.T) {
		doc := makeSPDXDoc([]miniComp{
			{id: "SPDXRef-A", name: "a", version: "1.0.0"},
			{id: "SPDXRef-B", name: "b", version: ""},
		})

		got := CompWithVersion(doc)
		assert.InDelta(t, 5.0, got.Score, 0.0001) // 10 * (1/2)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("none have versions → 0.0", func(t *testing.T) {
		doc := makeSPDXDoc([]miniComp{
			{id: "SPDXRef-A", name: "a", version: ""},
			{id: "SPDXRef-B", name: "b", version: ""},
		})

		got := CompWithVersion(doc)

		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("no components → N/A", func(t *testing.T) {
		doc := makeSPDXDoc(nil)

		got := CompWithVersion(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})
}

func TestCompWithVersion_CycloneDX(t *testing.T) {
	doc := makeCDXDoc([]miniComp{
		{id: "bom-ref-a", name: "a", version: "3.1.4"},
		{id: "bom-ref-b", name: "b", version: "2.0.0"},
		{id: "bom-ref-c", name: "c", version: ""},
	})

	got := CompWithVersion(doc)

	// 2/3 → 6.666..., rounded/float compared with delta
	assert.InDelta(t, (10.0*2.0)/3.0, got.Score, 0.0001)
	assert.Equal(t, "add to 1 component", got.Desc)
	assert.False(t, got.Ignore)
}

func TestCompWithUniqLocalIDs_SPDX(t *testing.T) {
	t.Run("all have local IDs → 10.0", func(t *testing.T) {
		doc := makeSPDXDoc([]miniComp{
			{id: "SPDXRef-A", name: "a", version: "1.0.0"},
			{id: "SPDXRef-B", name: "b", version: "2.0.0"},
		})

		got := CompWithUniqLocalIDs(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc) // “unique” per current impl = “present”
		assert.False(t, got.Ignore)
	})

	t.Run("some missing IDs → partial", func(t *testing.T) {
		doc := makeSPDXDoc([]miniComp{
			{id: "SPDXRef-A", name: "a", version: "1.0.0"},
			{id: "", name: "b", version: "2.0.0"},
		})

		out := CompWithUniqLocalIDs(doc)
		assert.InDelta(t, 5.0, out.Score, 0.0001) // 10 * (1/2)
		assert.Equal(t, "add to 1 component", out.Desc)
		assert.False(t, out.Ignore)
	})

	t.Run("no components → N/A", func(t *testing.T) {
		doc := makeSPDXDoc(nil)

		out := CompWithUniqLocalIDs(doc)
		assert.InDelta(t, 0.0, out.Score, 0.0001)
		assert.Equal(t, "N/A (no components)", out.Desc)
		assert.True(t, out.Ignore)
	})
}

func TestCompWithUniqLocalIDs_CycloneDX(t *testing.T) {
	doc := makeCDXDoc([]miniComp{
		{id: "bom-ref-a", name: "a", version: "1.0.0"},
		{id: "", name: "b", version: "2.0.0"},
		{id: "bom-ref-c", name: "c", version: "2.0.1"},
	})

	got := CompWithUniqLocalIDs(doc)
	// 2/3 → 6.666...
	assert.InDelta(t, (10.0*2.0)/3.0, got.Score, 0.0001)
	assert.Equal(t, "add to 1 component", got.Desc)
	assert.False(t, got.Ignore)
}
