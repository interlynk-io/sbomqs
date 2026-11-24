// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// ENISA — SBOM Author (Person-only)
// ============================================================

var enisaCdxSBOMAuthorPerson = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Samantha Wright",
        "email": "samantha.wright@example.com"
      }
    ]
  },
  "components": []
}
`)

var enisaCdxSBOMAuthorOrganization = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Acme Corp",
        "email": "corp@example.com"
      }
    ]
  },
  "components": []
}
`)

var enisaSpdxSBOMAuthorPerson = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

var enisaSpdxSBOMAuthorOrganization = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization: Acme Corp (corp@example.com)"
    ]
  },
  "packages": []
}
`)

var enisaSpdxSBOMAuthorTool = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: sbomqs-2.1.0"
    ]
  },
  "packages": []
}
`)

var enisaCdxSBOMAuthorAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var enisaSpdxSBOMAuthorAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {},
  "packages": []
}
`)

// SPDX 3.0 Person author
var enisaSpdx3SBOMAuthorPerson = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "test-spdx3-doc",
      "creationInfo": "_:creationinfo"
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2025-01-01T00:00:00Z",
      "createdBy": ["_:person1"]
    },
    {
      "type": "Person",
      "@id": "_:person1",
      "name": "John Doe"
    }
  ]
}
`)

// SPDX 3.0 Organization author
var enisaSpdx3SBOMAuthorOrganization = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "test-spdx3-doc",
      "creationInfo": "_:creationinfo"
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2025-01-01T00:00:00Z",
      "createdBy": ["_:org1"]
    },
    {
      "type": "Organization",
      "@id": "_:org1",
      "name": "Acme Corp"
    }
  ]
}
`)

func TestENISASBOMAuthor(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxPersonAuthorAccepted", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMAuthorPerson, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Samantha Wright", got.CheckValue)
	})

	t.Run("cdxOrganizationAuthorTreatedAsPerson", func(t *testing.T) {
		// CDX metadata authors have no "type" field; parser always returns "person".
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMAuthorOrganization, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Acme Corp", got.CheckValue)
	})

	t.Run("spdxPersonAuthorAccepted", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxSBOMAuthorPerson, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Samantha Wright", got.CheckValue)
	})

	t.Run("spdxOrganizationAuthorRejected", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxSBOMAuthorOrganization, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		// CheckValue is empty because the code returns "" when rejecting Organization.
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("spdxToolAuthorNotInAuthors", func(t *testing.T) {
		// SPDX Tool creators are placed in doc.Tools(), not doc.Authors().
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxSBOMAuthorTool, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("cdxAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("spdxAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("spdx3PersonAuthorAccepted", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdx3SBOMAuthorPerson, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "John Doe", got.CheckValue)
	})

	t.Run("spdx3OrganizationAuthorRejected", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdx3SBOMAuthorOrganization, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — SBOM Timestamp
// ============================================================

var enisaCdxSBOMTimestamp = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z"
  },
  "components": []
}
`)

var enisaSpdxSBOMTimestamp = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z"
  },
  "packages": []
}
`)

var enisaCdxSBOMTimestampInvalid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "not-a-timestamp"
  },
  "components": []
}
`)

var enisaCdxSBOMTimestampAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

func TestENISASBOMTimestamp(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_TIMESTAMP, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "2025-01-01T00:00:00Z", got.CheckValue)
	})

	t.Run("spdxValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxSBOMTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_TIMESTAMP, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "2025-01-01T00:00:00Z", got.CheckValue)
	})

	t.Run("cdxInvalidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMTimestampInvalid, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_TIMESTAMP, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "not-a-timestamp", got.CheckValue)
	})

	t.Run("cdxTimestampAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMTimestampAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_TIMESTAMP, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — SBOM Tool Name
// ============================================================

var enisaCdxSBOMToolName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "Awesome Tool",
          "version": "1.0.0"
        }
      ]
    }
  },
  "components": []
}
`)

var enisaSpdxSBOMToolName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["Tool: Awesome Tool-1.0.0"]
  },
  "packages": []
}
`)

var enisaCdxSBOMToolNameAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

func TestENISASBOMToolName(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxToolNamePresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMToolName, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMToolName(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_TOOL_NAME, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Awesome Tool", got.CheckValue)
	})

	t.Run("spdxToolNamePresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxSBOMToolName, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMToolName(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_TOOL_NAME, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Awesome Tool", got.CheckValue)
	})

	t.Run("cdxToolNameAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMToolNameAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMToolName(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_TOOL_NAME, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — SBOM Generation Context
// ============================================================

var enisaCdxSBOMGenerationContext = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      { "phase": "build" }
    ]
  },
  "components": []
}
`)

var enisaSpdxSBOMGenerationContext = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "comment": "Generated during CI/CD build"
  },
  "packages": []
}
`)

var enisaCdxSBOMGenerationContextAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

func TestENISASBOMGenerationContext(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxLifecyclePresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMGenerationContext, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMGenerationContext(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_GENERATION_CONTEXT, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "build", got.CheckValue)
	})

	t.Run("spdxCommentPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxSBOMGenerationContext, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMGenerationContext(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_GENERATION_CONTEXT, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Generated during CI/CD build", got.CheckValue)
	})

	t.Run("cdxContextAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxSBOMGenerationContextAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := enisaSBOMGenerationContext(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_SBOM_GENERATION_CONTEXT, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — Component Producer (Person-only)
// ============================================================

var enisaCdxCompProducerPerson = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "pkg",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0",
      "authors": [
        {
          "name": "Jane Doe",
          "email": "jane@example.com"
        }
      ]
    }
  ]
}
`)

var enisaCdxCompProducerOrganization = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "pkg",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0",
      "authors": [
        {
          "name": "Acme Corp"
        }
      ]
    }
  ]
}
`)

var enisaSpdxCompProducerPerson = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "pkg",
      "versionInfo": "1.0.0",
      "originator": "Person: Jane Doe (jane@example.com)"
    }
  ]
}
`)

var enisaSpdxCompProducerOrganization = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "pkg",
      "versionInfo": "1.0.0",
      "originator": "Organization: Acme Corp"
    }
  ]
}
`)

var enisaCdxCompProducerAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
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

func TestENISACompProducer(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxPersonProducerEmptyType", func(t *testing.T) {
		// CDX component authors have no "type" field; parser returns "".
		// enisaCompProducer requires "person" match, so score is 0.
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompProducerPerson, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompProducer(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_PRODUCER, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("cdxOrganizationProducerTreatedAsPerson", func(t *testing.T) {
		// CDX component authors have no "type" field; parser returns "".
		// enisaCompProducer requires "person" match, so score is 0 (same as Person).
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompProducerOrganization, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompProducer(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_PRODUCER, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("spdxPersonProducerNotMapped", func(t *testing.T) {
		// SPDX originator is not mapped to comp.Authors(); comp.Authors() is empty.
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxCompProducerPerson, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompProducer(comps[0], "SPDXRef-Pkg")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_PRODUCER, got.CheckKey)
		assert.Equal(t, "SPDXRef-Pkg", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("spdxOrganizationProducerNotMapped", func(t *testing.T) {
		// SPDX originator is not mapped to comp.Authors(); comp.Authors() is empty.
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaSpdxCompProducerOrganization, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompProducer(comps[0], "SPDXRef-Pkg")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_PRODUCER, got.CheckKey)
		assert.Equal(t, "SPDXRef-Pkg", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("cdxProducerAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompProducerAbsent, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompProducer(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_PRODUCER, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — Component Name
// ============================================================

var enisaCdxCompName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
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

var enisaCdxCompNameEmpty = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0"
    }
  ]
}
`)

func TestENISACompName(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompNamePresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompName, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompName(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_NAME, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "pkg", got.CheckValue)
	})

	t.Run("cdxCompNameEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompName(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_NAME, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — Component Version
// ============================================================

func TestENISACompVersion(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompVersionPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompName, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompVersion(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_VERSION, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "1.0.0", got.CheckValue)
	})
}

// ============================================================
// ENISA — Component Unique ID
// ============================================================

var enisaCdxCompUniqID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "pkg",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0",
      "purl": "pkg:npm/pkg@1.0.0"
    }
  ]
}
`)

var enisaCdxCompUniqIDAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
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

func TestENISACompUniqID(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompPURLPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompUniqID, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompUniqID(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_UNIQ_ID, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "pkg:npm/pkg@1.0.0", got.CheckValue)
	})

	t.Run("cdxCompUniqIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompUniqIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompUniqID(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_UNIQ_ID, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — Component Hash
// ============================================================

var enisaCdxCompHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "pkg",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      ]
    }
  ]
}
`)

var enisaCdxCompHashAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
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

func TestENISACompHash(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompHashValuePresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompHash, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompHashValue(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_HASH_VALUE, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Contains(t, got.CheckValue, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	})

	t.Run("cdxCompHashAlgoPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompHash, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompHashAlgo(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_HASH_ALGO, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "SHA-256", got.CheckValue)
	})

	t.Run("cdxCompHashAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompHashAbsent, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompHashValue(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_HASH_VALUE, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — Component License
// ============================================================

var enisaCdxCompLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "pkg",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ]
}
`)

var enisaCdxCompLicenseAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
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

func TestENISACompLicense(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompLicensePresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompLicense, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompLicense(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_LICENSE, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "MIT", got.CheckValue)
	})

	t.Run("cdxCompLicenseAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompLicenseAbsent, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 1)

		got := enisaCompLicense(comps[0], "pkg@1.0.0")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_LICENSE, got.CheckKey)
		assert.Equal(t, "pkg@1.0.0", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

// ============================================================
// ENISA — Component Relationships
// ============================================================

var enisaCdxCompRelationships = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app-1.0",
      "dependsOn": ["library-a"]
    }
  ]
}
`)

var enisaCdxCompRelationshipsAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    }
  ]
}
`)

func TestENISACompRelationships(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxPrimaryCompRelationshipsPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompRelationships, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 2) // metadata.component + components[]

		// Find the primary component
		var primaryComp sbom.GetComponent
		for _, c := range comps {
			if c.GetID() == "app-1.0" {
				primaryComp = c
				break
			}
		}
		require.NotNil(t, primaryComp)

		got := enisaCompRelationships(doc, primaryComp, "app-1.0")

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_RELATIONSHIPS, got.CheckKey)
		assert.Equal(t, "app-1.0", got.ID)
		assert.Contains(t, got.CheckValue, "primary component declares")
	})

	t.Run("cdxCompRelationshipsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, enisaCdxCompRelationshipsAbsent, sbom.Signature{})
		require.NoError(t, err)

		comps := doc.Components()
		require.Len(t, comps, 2) // metadata.component + components[]

		// Find the library component (not primary)
		var libComp sbom.GetComponent
		for _, c := range comps {
			if c.GetID() == "library-a" {
				libComp = c
				break
			}
		}
		require.NotNil(t, libComp)

		got := enisaCompRelationships(doc, libComp, "library-a")

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, ENISA_COMP_RELATIONSHIPS, got.CheckKey)
		assert.Equal(t, "library-a", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}
