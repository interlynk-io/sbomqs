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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
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
		assert.Equal(t, "0/2 have dependencies", got.Desc)
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
		assert.Equal(t, "1/2 have dependencies", got.Desc)
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
		assert.Equal(t, "2/2 have dependencies", got.Desc)
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
		assert.Equal(t, "absent", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithPrimaryComponent", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
		})

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "identified", got.Desc)
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
		assert.Equal(t, "0/2 have source URIs", got.Desc)
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
		assert.Equal(t, "1/2 have source URIs", got.Desc)
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
		assert.Equal(t, "2/2 have source URIs", got.Desc)
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
		assert.Equal(t, "0/2 have suppliers", got.Desc)
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
		assert.Equal(t, "1/2 have suppliers", got.Desc)
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
		assert.Equal(t, "2/2 have suppliers", got.Desc)
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
		assert.Equal(t, "0/2 have type", got.Desc)
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
		assert.Equal(t, "1/2 have type", got.Desc)
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
		assert.Equal(t, "2/2 have type", got.Desc)
		assert.False(t, got.Ignore)
	})
}
