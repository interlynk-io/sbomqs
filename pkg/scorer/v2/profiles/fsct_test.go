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
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var spdxSBOMAuthorWithNameAndEmail = []byte(`
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

var cdxSBOMAuthorAndTool = []byte(`
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
    ],
	"tools": [
      {
        "vendor": "CycloneDX",
        "name": "cyclonedx-gomod",
        "version": "v1.9.0",
        "hashes": [
          {
            "alg": "MD5",
            "content": "c3d43dcbd0fe759f08bf015a813a9b8a"
          },
          {
            "alg": "SHA-256",
            "content": "64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21"
          }
        ],
        "externalReferences": [
          {
            "url": "https://github.com/CycloneDX/cyclonedx-gomod",
            "type": "vcs"
          },
          {
            "url": "https://cyclonedx.org",
            "type": "website"
          }
        ]
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorAndTool = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)",
      "Tool: cyclonedx-gomod-v1.9.0"
    ]
  },
  "packages": []
}
`)

var cdxSBOMMultipleAuthorsWithNameAndEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
        {
            "name": "Interlynk",
            "email": "hello@interlynk.io",
            "phone": "800-555-1212"
        },
        {
            "name": "VulnCon SBOM Generation Workshop",
            "email": "vulncon@sbom.dev",
            "phone": "800-555-1313"
        },
        {
            "name": "Interlynk",
            "email": "hi@interlynk.io",
            "phone": "800-555-1414"
        }
    ]
  },
  "components": []
}
`)

var spdxSBOMMultipleAuthorWithNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization: Interlynk (hello@interlynk.io, 800-555-1212)",
      "Organization: VulnCon SBOM Generation Workshop (vulncon@sbom.dev, 800-555-1313)",
      "Organization: Interlynk (hi@interlynk.io, 800-555-1414)"
    ]
  },
  "packages": []
}
`)

var cdxSBOMMultipleAuthorsAndTools = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
        {
            "name": "Interlynk",
            "email": "hello@interlynk.io",
            "phone": "800-555-1212"
        },
        {
            "name": "VulnCon SBOM Generation Workshop",
            "email": "vulncon@sbom.dev",
            "phone": "800-555-1313"
        },
        {
            "name": "Interlynk",
            "email": "hi@interlynk.io",
            "phone": "800-555-1414"
        }
    ],
	"tools": [
      {
        "vendor": "CycloneDX",
        "name": "cyclonedx-gomod",
        "version": "v1.9.0",
        "hashes": [
          {
            "alg": "MD5",
            "content": "c3d43dcbd0fe759f08bf015a813a9b8a"
          },
          {
            "alg": "SHA-256",
            "content": "64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21"
          }
        ],
        "externalReferences": [
          {
            "url": "https://github.com/CycloneDX/cyclonedx-gomod",
            "type": "vcs"
          },
          {
            "url": "https://cyclonedx.org",
            "type": "website"
          }
        ]
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMMultipleAuthorsAndTools = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization: Interlynk (hello@interlynk.io, 800-555-1212)",
      "Organization: VulnCon SBOM Generation Workshop (vulncon@sbom.dev, 800-555-1313)",
      "Organization: Interlynk (hi@interlynk.io, 800-555-1414)",
      "Tool: cyclonedx-gomod-v1.9.0"
    ]
  },
  "packages": []
}
`)

var cdxSBOMAuthorsWithEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "",
        "email": ""
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorsWithEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [""]
  },
  "packages": []
}
`)

var cdxSBOMTool = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
	"tools": [
      {
        "vendor": "CycloneDX",
        "name": "cyclonedx-gomod",
        "version": "v1.9.0",
        "hashes": [
          {
            "alg": "MD5",
            "content": "c3d43dcbd0fe759f08bf015a813a9b8a"
          },
          {
            "alg": "SHA-256",
            "content": "64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21"
          }
        ],
        "externalReferences": [
          {
            "url": "https://github.com/CycloneDX/cyclonedx-gomod",
            "type": "vcs"
          },
          {
            "url": "https://cyclonedx.org",
            "type": "website"
          }
        ]
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMTool = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: cyclonedx-gomod-v1.9.0"
    ]
  },
  "packages": []
}
`)

func TestFSCTSBOMAuthor(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMAuthorWithNameAndEmail
	t.Run("cdxSBOMAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithNameAndEmail
	t.Run("spdxSBOMAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationNameAndEmail
	t.Run("spdxSBOMAuthorWithOrganizationNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorAndTool
	t.Run("cdxSBOMAuthorAndTool", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorAndTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorAndTool
	t.Run("spdxSBOMAuthorAndTool", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAndTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMMultipleAuthorsWithNameAndEmail
	t.Run("cdxSBOMMultipleAuthorsWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMultipleAuthorsWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMMultipleAuthorWithNameAndEmail
	t.Run("spdxSBOMMultipleAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMultipleAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMMultipleAuthorsAndTools
	t.Run("cdxSBOMMultipleAuthorsAndTools", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMultipleAuthorsAndTools, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMMultipleAuthorsAndTools
	t.Run("spdxSBOMMultipleAuthorsAndTools", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMultipleAuthorsAndTools, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithEmail
	t.Run("cdxSBOMAuthorWithEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonEmail
	t.Run("spdxSBOMAuthorWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationEmail
	t.Run("spdxSBOMAuthorWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithName
	t.Run("cdxSBOMAuthorWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonName
	t.Run("spdxSBOMAuthorWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationName
	t.Run("spdxSBOMAuthorWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author entity explicitly identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsAbsent
	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorAbsent
	t.Run("spdxSBOMAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorMissing
	t.Run("cdxSBOMAuthorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorPersonMissing
	t.Run("spdxSBOMAuthorPersonMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorPersonMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorOrganizationMissing
	t.Run("spdxSBOMAuthorOrganizationMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorOrganizationMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithEmptyString
	t.Run("cdxSBOMAuthorsWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorsWithEmptyString
	t.Run("spdxSBOMAuthorsWithEmptyString", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyString, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMAuthorsWithEmptyArray
	t.Run("cdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithEmptyArrayObject
	t.Run("cdxSBOMAuthorsWithEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorsWithEmptyArray
	t.Run("spdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithWrongType
	t.Run("cdxSBOMAuthorsWithWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// spdxSBOMCreatorsWithWrongTypeSomeValue
	t.Run("spdxSBOMCreatorsWithWrongTypeSomeValue", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWithWrongTypeSomeValue, sbom.Signature{})
		require.Error(t, err)
	})

	// spdxSBOMCreatorsWithWhitespace
	t.Run("spdxSBOMCreatorsWithWhitespace", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWithWhitespace, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMTool
	t.Run("cdxSBOMTool", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMTool
	t.Run("spdxSBOMAutspdxSBOMToolhorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add authors", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxCompSupplierWithNameURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ]
      }
    }
	
  ]
}
`)

var cdxCompSupplierWithURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "url": [
          "https://example.com"
        ]
      }
    }
	
  ]
}
`)

var cdxCompSupplierWithContactNameAndEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "professional.services@example.com"
          }
        ]
      }
    }
	
  ]
}
`)

var cdxCompSupplierWithContactName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "contact": [
          {
            "name": "Acme Professional Services"
          }
        ]
      }
    }
	
  ]
}
`)

var cdxCompSupplierWithContactEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {
        "contact": [
          {
            "email": "professional.services@example.com"
          }
        ]
      }
    }
	
  ]
}
`)

var cdxCompSupplierMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0",
      "supplier": {}
    }
	
  ]
}
`)

func TestFSCTCompSupplier(t *testing.T) {
	ctx := context.Background()

	// cdxCompSupplierWithURL
	t.Run("cdxCompSupplierWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// t.Run("cdxCompSupplierWithContactNameAndEmail", func(t *testing.T) {
	// 	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithContactNameAndEmail, sbom.Signature{})
	// 	require.NoError(t, err)

	// 	got := FSCTCompSupplier(doc)

	// 	assert.InDelta(t, 10.0, got.Score, 1e-9)
	// 	assert.Equal(t, "supplier information missing for some components", got.Desc)
	// 	assert.False(t, got.Ignore)
	// })
}
