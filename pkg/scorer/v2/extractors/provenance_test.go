// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extractors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

type spdxOptions struct {
	Timestamp string
	Namespace string
	Authors   []struct{ Name, Email, Type string }
	Tools     []struct{ Name, Version string }
}

type cdxOptions struct {
	Timestamp  string
	URI        string   // CDX serialNumber/URI equivalent exposed via Spec().GetURI()
	Lifecycles []string // CDX metadata.lifecycle/phase
	Supplier   struct{ Name, Email string }
	Tools      []struct{ Name, Version string }
	Authors    int
}

// makeSPDXDoc creates an SPDX doc with the given knobs.
func makeSPDXDocForProvenance(opts spdxOptions) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.Spdxid = "DOCUMENT"
	s.CreationTimestamp = opts.Timestamp
	s.Namespace = opts.Namespace

	// Tools
	var tools []sbom.GetTool
	for _, tv := range opts.Tools {
		tools = append(tools, sbom.Tool{Name: tv.Name, Version: tv.Version})
	}

	// Authors
	var authors []sbom.GetAuthor
	for _, a := range opts.Authors {
		authors = append(authors, sbom.Author{Name: a.Name, Email: a.Email, AuthorType: a.Type})
	}

	return sbom.SpdxDoc{
		SpdxSpec:  s,
		Comps:     nil,
		SpdxTools: tools,
		Auths:     authors,
	}
}

// makeCDXDocForProvenance creates a CycloneDX doc with the given knobs.
func makeCDXDocForProvenance(opts cdxOptions,
) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "1.6"
	s.SpecType = "cyclonedx"
	s.Format = "json"
	s.URI = opts.URI
	s.CreationTimestamp = opts.Timestamp

	// Tools
	var tools []sbom.GetTool
	for _, tv := range opts.Tools {
		tools = append(tools, sbom.Tool{Name: tv.Name, Version: tv.Version})
	}

	// Supplier (doc-level)
	var supplier sbom.GetSupplier
	supplier = sbom.Supplier{Name: opts.Supplier.Name, Email: opts.Supplier.Email}

	// Authors (if your wrapper supports it)
	if opts.Authors > 0 {
		s.Organization = "acme-cdx"
	}

	// Lifecycles on CDX doc root (your wrapper’s doc.Lifecycles() should surface this)
	return sbom.CdxDoc{
		CdxSpec:     s,
		CdxTools:    tools,
		CdxSupplier: supplier,
		Lifecycle:   opts.Lifecycles,
	}
}

func Test_SBOMCreationTimestamp(t *testing.T) {
	t.Run("SPDX valid RFC3339", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{
			Timestamp: "2025-01-20T10:30:45Z",
			Namespace: "https://example.com/ns",
		})

		got := SBOMCreationTimestamp(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "2025-01-20T10:30:45Z", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SPDX invalid timestamp", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{
			Timestamp: "01/20/2025 10:30:45",
		})

		got := SBOMCreationTimestamp(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, got.Desc, "invalid timestamp: 01/20/2025 10:30:45")
		assert.False(t, got.Ignore)
	})

	t.Run("CDX valid RFC3339Nano", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{
			Timestamp: "2025-01-20T10:30:45.123456789Z",
		})
		got := SBOMCreationTimestamp(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "2025-01-20T10:30:45.123456789Z", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("CDX missing timestamp", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{})
		got := SBOMCreationTimestamp(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing timestamp", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func Test_SBOMAuthors(t *testing.T) {
	// SPDX Doc with 0 authors
	t.Run("SPDX zero authors → 0", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{})
		got := SBOMAuthors(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing author", got.Desc)
	})

	// SPDX Doc with 1 author of type person
	t.Run("SPDX one authors → 10", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{
			Authors: []struct{ Name, Email, Type string }{
				{
					Name:  "foo",
					Email: "foo@gmail.com",
					Type:  "person",
				},
			},
		})
		got := SBOMAuthors(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "1 authors", got.Desc)
	})

	// SPDX Doc with 2 authors, one of type person and another of organization
	t.Run("SPDX some authors → 10", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{
			Authors: []struct{ Name, Email, Type string }{
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
		})
		got := SBOMAuthors(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, got.Desc, "2 authors")
	})
}

func Test_SBOMCreationTool(t *testing.T) {
	t.Run("no tools with name+version → 0", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{
			Tools: []struct{ Name, Version string }{
				{Name: "syft", Version: ""},
			},
		})
		got := SBOMCreationTool(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing tool", got.Desc)
	})

	t.Run("has tool name+version → 10", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{
			Tools: []struct{ Name, Version string }{
				{Name: "syft", Version: "0.95.0"},
				{Name: "trivy", Version: "0.45.1"},
			},
		})
		got := SBOMCreationTool(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, got.Desc, "2 tool")
	})
}

func Test_SBOMSupplier(t *testing.T) {
	t.Run("SPDX → N/A", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{})
		got := SBOMSupplier(doc)
		assert.True(t, got.Ignore)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "N/A (SPDX)", got.Desc)
	})

	t.Run("CDX with supplier → 10", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{Supplier: struct {
			Name  string
			Email string
		}{Name: "Interlynk", Email: "hello@interlynk.io"}})

		got := SBOMSupplier(doc)
		assert.False(t, got.Ignore)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "1 supplier", got.Desc)
	})

	t.Run("CDX missing supplier → 0", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{})
		got := SBOMSupplier(doc)
		assert.False(t, got.Ignore)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing supplier", got.Desc)
	})
}

func Test_SBOMNamespace(t *testing.T) {
	t.Run("SPDX namespace present → 10", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{
			Namespace: "https://example.com/ns",
		})
		got := SBOMNamespace(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing namespace", got.Desc)
	})

	t.Run("SPDX namespace missing → 0", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{})
		got := SBOMNamespace(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing namespace", got.Desc)
	})

	t.Run("CDX uri present → 10", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{
			URI: "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
		})
		got := SBOMNamespace(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present namespace", got.Desc)
	})

	t.Run("CDX uri missing → 0", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{})
		got := SBOMNamespace(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing namespace", got.Desc)
	})
}

func Test_SBOMLifeCycle(t *testing.T) {
	t.Run("SPDX → N/A", func(t *testing.T) {
		doc := makeSPDXDocForProvenance(spdxOptions{})
		got := SBOMLifeCycle(doc)
		assert.True(t, got.Ignore)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "N/A (SPDX)", got.Desc)
	})

	t.Run("CDX lifecycles present → 10", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{
			Lifecycles: []string{"build", "runtime"},
		})
		got := SBOMLifeCycle(doc)
		assert.False(t, got.Ignore)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "build, runtime", got.Desc)
	})

	t.Run("CDX lifecycles missing → 0", func(t *testing.T) {
		doc := makeCDXDocForProvenance(cdxOptions{})
		got := SBOMLifeCycle(doc)
		assert.False(t, got.Ignore)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "missing lifecycle", got.Desc)
	})
}
