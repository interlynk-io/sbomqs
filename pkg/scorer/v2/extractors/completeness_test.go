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
	"fmt"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/stretchr/testify/assert"
)

type miniComp2 struct {
	id               string
	name             string
	version          string
	srcURL           string
	supplierName     string
	supplierEmail    string
	supplierURL      string
	RelElementA      string
	RelElementB      string
	RelType          string
	primaryPurpose   string
	hasRelationships bool
	depsCount        int
}

type spdxDocOpts2 struct {
	namespace   string
	withPrimary bool
	comps       []miniComp2
}

type cdxDocOpts2 struct {
	uri         string
	withPrimary bool
	comps       []miniComp2
}

func makeSPDXDocForCompleteness(opts spdxDocOpts2) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.Spdxid = "DOCUMENT"
	s.Namespace = opts.namespace
	s.CreationTimestamp = "2025-01-01T00:00:00Z"

	var comps []sbom.GetComponent
	var deps []sbom.GetRelation

	for _, c := range opts.comps {
		p := sbom.NewComponent()
		p.ID = c.id
		p.Name = c.name
		p.Version = c.version
		p.SourceCodeURL = c.srcURL
		if c.supplierName != "" || c.supplierEmail != "" || c.supplierURL != "" {
			p.Supplier = sbom.Supplier{Name: c.supplierName, Email: c.supplierEmail, URL: c.supplierURL}
		}
		p.Purpose = c.primaryPurpose
		p.HasRelationships = c.hasRelationships
		p.Count = c.depsCount

		var dep sbom.Relation
		dep.From = c.RelElementA
		dep.To = c.RelElementB

		deps = append(deps, dep)
		comps = append(comps, p)
	}

	pc := sbom.PrimaryComp{}
	pc.Present = opts.withPrimary

	return sbom.SpdxDoc{
		SpdxSpec:         s,
		Comps:            comps,
		Rels:             deps,
		PrimaryComponent: pc,
	}
}

func TestCompWithDependencies(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoDependencies", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", hasRelationships: false, depsCount: 0},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", hasRelationships: false, depsCount: 0},
			},
		})

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "2 min 1 dependency (completeness unknown)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithDependency", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", hasRelationships: true, depsCount: 2},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", hasRelationships: false, depsCount: 0},
			},
		})
		got := CompWithDependencies(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1 min 1 dependency (completeness unknown)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithDependency", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", hasRelationships: true, depsCount: 2},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", hasRelationships: true, depsCount: 3},
			},
		})
		got := CompWithDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "0 min 1 dependency (completeness unknown)", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithPrimaryComponent(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: false,
		})

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithPrimaryComponent", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
		})

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithSourceCode(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoSourceCodeURL", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithSourceCodeURL", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", srcURL: "https://github.com/demo/foo"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})
		got := CompWithSourceCode(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithSourceCodeURL", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", srcURL: "https://github.com/demo/foo"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", srcURL: "https://github.com/demo/bar"},
			},
		})
		got := CompWithSourceCode(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithSupplier(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoSupplier", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})

		got := CompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithSupplier", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", supplierName: "redhat", supplierEmail: "hello@redhat.com"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})
		got := CompWithSupplier(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithSupplier", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", supplierName: "redhat", supplierEmail: "hello@redhat.com"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", supplierName: "ubuntu", supplierEmail: "hello@ubuntu.com"},
			},
		})
		got := CompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithPackageType(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoPackageType", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithPackageType", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", primaryPurpose: "container"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})
		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithPackageType", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", primaryPurpose: "library"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", primaryPurpose: "application"},
			},
		})
		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

type miniComposition struct {
	scope           sbom.CompositionScope
	aggregate       sbom.CompositionAggregate
	dependencies    []string
	assemblies      []string
	vulnerabilities []string
}

func makeCDXDocForCompleteness(comps []miniComp2, compositions []miniComposition) sbom.Document {
	var components []sbom.GetComponent
	for _, c := range comps {
		p := sbom.NewComponent()
		p.ID = c.id
		p.Name = c.name
		p.Version = c.version
		components = append(components, p)
	}

	var csts []sbom.GetComposition
	for i, mc := range compositions {

		cst := sbom.NewComposition(
			fmt.Sprintf("cmp-%d", i),
			mc.scope,
			mc.aggregate,
			mc.dependencies,
			mc.assemblies,
			mc.vulnerabilities,
		)

		csts = append(csts, cst)
	}

	spec := sbom.NewSpec()
	spec.SpecType = string(sbom.SBOMSpecCDX)
	spec.Version = "1.6"

	return sbom.CdxDoc{
		CdxSpec:      spec,
		Comps:        components,
		Compositions: csts,
	}
}

func TestCompWithDeclaredCompleteness_NoComponents(t *testing.T) {
	doc := makeCDXDocForCompleteness(nil, nil)

	got := CompWithDeclaredCompleteness(doc)

	assert.True(t, got.Ignore)
	assert.Equal(t, "N/A (no components)", got.Desc)
}

func TestCompWithDeclaredCompleteness_SPDX(t *testing.T) {
	doc := makeSPDXDocForCompleteness(spdxDocOpts2{
		withPrimary: true,
		comps: []miniComp2{
			{id: "SPDXRef-A", name: "a", version: "1.0"},
		},
	})

	got := CompWithDeclaredCompleteness(doc)

	assert.True(t, got.Ignore)
	assert.Equal(t, formulae.NonSupportedSPDXField(), got.Desc)
}

func TestCompWithDeclaredCompleteness_NoCompositions(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "B"},
		},
		nil,
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "add to 2 components", got.Desc)
}

func TestCompWithDeclaredCompleteness_GlobalComplete(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "B"},
		},
		[]miniComposition{
			{
				scope:     sbom.ScopeGlobal,
				aggregate: sbom.AggregateComplete,
			},
		},
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 10.0, got.Score, 1e-9)
	assert.Equal(t, "complete", got.Desc)
}

func TestCompWithDeclaredCompleteness_ComponentScoped(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "bom-refB"},
		},
		[]miniComposition{
			{
				scope:        sbom.ScopeDependencies,
				aggregate:    sbom.AggregateComplete,
				dependencies: []string{"bom-refA"},
			},
		},
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
}

func TestCompWithDeclaredCompleteness_Mixed(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "bom-refB"},
		},
		[]miniComposition{
			{
				scope:     sbom.ScopeGlobal,
				aggregate: sbom.AggregateUnknown,
			},
			{
				scope:      sbom.ScopeAssemblies,
				aggregate:  sbom.AggregateComplete,
				assemblies: []string{"bom-refB"},
			},
		},
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
}
