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

var cdxTwoCompWithOneSupplierMissing = []byte(`
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
    },
    {
      "type": "library",
      "name": "Beta Library",
      "version": "1.0",
      "supplier": {}
    }
	
  ]
}
`)

var cdxThreeCompWithOneSupplierMissing = []byte(`
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
    },
    {
      "bom-ref": "pkg:golang/github.com/sigstore/rekor@v1.3.9?type=module",
      "type": "library",
      "name": "github.com/sigstore/rekor",
      "version": "v1.3.9",
      "supplier": {
        "name": "Sigstore",
        "url": [
            "https://sigstore.dev"
        ]
      }
    },
    {
      "type": "library",
      "name": "Beta Library",
      "version": "1.0",
      "supplier": {}
    }
  ]
}
`)

var cdxTwoCompWithBothSupplierMissing = []byte(`
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
    },
    {
      "type": "library",
      "name": "Beta Library",
      "version": "1.0",
      "supplier": {}
    }
	
  ]
}
`)

var cdxTwoCompWithBothSupplierAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0"
    },
    {
      "type": "library",
      "name": "Beta Library",
      "version": "1.0"
    }
	
  ]
}
`)

func TestFSCTCompSupplier(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompSupplierWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierAsPersonWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsPersonWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierAsOrganizationWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsOrganizationWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithNameURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithContactNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithContactNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithContactName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithContactName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithContactEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithContactEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "supplier identified for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierWithPersonNameEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithWhiteSpaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithWhiteSpaceName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithOneSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithOneSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "supplier declared for 1 components; missing for 1", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxThreeCompWithOneSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxThreeCompWithOneSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 6.666666666666666, got.Score, 1e-9)
		assert.Equal(t, "supplier declared for 2 components; missing for 1", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithBothSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithBothSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(2) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithBothSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithBothSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier information missing for all(2) components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxCompValidPURL = []byte(`
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
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1"
    }
  ]
}
`)

var spdxCompPURLValid = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0",
	  "externalRefs": [
		{
			"referenceType": "purl",
			"referenceLocator": "pkg:golang/github.com/pkg/errors@0.9.1",
			"referenceCategory": "PACKAGE-MANAGER"
		}
	  ]
    }
  ]
}
`)

var cdxCompPURLInValid = []byte(`
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
      "purl": "pkg:kskowo2ke8eiemdndn"
    }
  ]
}
`)

var spdxCompInValidPURL = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0",
	  "externalRefs": [
		{
			"referenceType": "purl",
			"referenceLocator": "kskowo2ke8eiemdndn",
			"referenceCategory": "PACKAGE-MANAGER"
		}
	  ]
    }
  ]
}
`)

var cdxCompPURLWithEmptyString = []byte(`
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
      "purl": ""
    }
  ]
}
`)

var spdxCompPURLWithEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0",
	  "externalRefs": [
		{
			"referenceType": "purl",
			"referenceLocator": "",
			"referenceCategory": "PACKAGE-MANAGER"
		}
	  ]
    }
  ]
}
`)

var cdxCompPURLWhitespace = []byte(`
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
      "purl": "   "
    }
  ]
}
`)

var spdxCompPURLWhitespace = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0",
	  "externalRefs": [
		{
			"referenceType": "purl",
			"referenceLocator": "  ",
			"referenceCategory": "PACKAGE-MANAGER"
		}
	  ]
    }
  ]
}
`)

var cdxCompPURLAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "Acme Library",
      "version": "3.0"
    }
  ]
}
`)

var spdxCompPURLAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    }
  ]
}
`)

var cdxCompPURLWrongType = []byte(`
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
	  "purl": {}
    }
  ]
}
`)

var spdxCompPURLWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0",
	  "externalRefs": [
		{
			"referenceType": {},
			"referenceLocator": "  ",
			"referenceCategory": "PACKAGE-MANAGER"
		}
	  ]
    }
  ]
}
`)

var spdxCompWithMultiplePURL = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "github.com/Azure/azure-sdk-for-go/sdk/azcore",
      "versionInfo": "v1.17.0",
	  "externalRefs": [
		{
			"referenceType": "purl",
			"referenceLocator": "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0?type=module",
			"referenceCategory": "PACKAGE-MANAGER"
		},
		{
			"referenceType": "purl",
			"referenceLocator": "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0?type=module\u0026goos=linux\u0026goarch=amd64",
			"referenceCategory": "PACKAGE-MANAGER"
		}
	  ]
    }
  ]
}
`)

var cdxCompSWIDValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swid": {
        "tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1",
        "name": "Acme Application",
        "version": "9.1.1"
      }
    }
  ]
}
`)

var cdxCompSWIDInValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swid": {
        "tagId": "slkjj82398jwwAKL;LKCNMC",
        "name": "Acme Application",
        "version": "9.1.1"
      }
    }
  ]
}
`)

var cdxCompSWIDEmpty = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swid": {
        "tagId": "",
        "name": "Acme Application",
        "version": "9.1.1"
      }
    }
  ]
}
`)

var cdxCompSWIDMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swid": {}
    }
  ]
}
`)

var cdxCompSWIDAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1"
    }
  ]
}
`)

var cdxCompSWIDWhiteSpace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swid": {
        "tagId": "    "
      }
    }
  ]
}
`)

var cdxCompSWHIDValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swhid": ["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"]
    }
  ]
}
`)

var cdxCompSWHIDInValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swhid": ["94a9ed024d3859793618152ea559a168bbcbb5e2"]
    }
  ]
}
`)

var cdxCompSWHIDEmpty = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swhid": [""]

    }
  ]
}
`)

var cdxCompSWHIDMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swhid": []

    }
  ]
}
`)

var cdxCompSWHIDAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1"
    }
  ]
}
`)

var cdxCompSWHIDWhiteSpace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "swhid": ["      "]

    }
  ]
}
`)

///---------

var cdxCompOmniborIDValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "omniborId": ["gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"]
    }
  ]
}
`)

var cdxCompOmniborIDInValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "omniborId": ["gitoid:blob:sha1:jjj"]
    }
  ]
}
`)

var cdxCompOmniborIDEmpty = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "omniborId": [""]
    }
  ]
}
`)

var cdxCompOmniborIDMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "omniborId": []
    }
  ]
}
`)

var cdxCompOmniborIDAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1"
    }
  ]
}
`)

var cdxCompOmniborIDWhiteSpace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "author": "Acme Super Heros",
      "name": "Acme Application",
      "version": "9.1.1",
      "omniborId": ["     "]
    }
  ]
}
`)

var cdxTwoCompWithValidPURL = []byte(`
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
    "purl": "pkg:golang/github.com/pkg/errors@0.9.1"
  },
	{
    "bom-ref": "pkg:golang/cel.dev/expr@v0.19.1?type=module",
    "type": "library",
    "name": "cel.dev/expr",
    "version": "v0.19.1",
	  "purl": "pkg:golang/cel.dev/expr@v0.19.1?type=module\u0026goos=linux\u0026goarch=amd64"
    }
  ]
}
`)

var cdxTwoCompWithValidPURLAndCPE = []byte(`
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
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1",
	  "cpe": "cpe:2.3:a:acme:library:3.0:*:*:*:*:go:*:*"
    },
	{
      "bom-ref": "pkg:golang/cel.dev/expr@v0.19.1?type=module",
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
	  "purl": "pkg:golang/cel.dev/expr@v0.19.1?type=module\u0026goos=linux\u0026goarch=amd64",
	  "cpe": "cpe:/golang/cel.dev/expr:v0.19.1"
    }
  ]
}
`)

var cdxTwoCompWithValidPURLCPEAndSWID = []byte(`
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
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1",
	  "cpe": "cpe:2.3:a:acme:library:3.0:*:*:*:*:go:*:*",
	  "swid": {
		"tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_3.0",
		"name": "Acme Library",
		"version": "3.0"
	  }
    },
	{
      "bom-ref": "pkg:golang/cel.dev/expr@v0.19.1?type=module",
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
	  "purl": "pkg:golang/cel.dev/expr@v0.19.1?type=module\u0026goos=linux\u0026goarch=amd64",
	  "cpe": "cpe:/golang/cel.dev/expr:v0.19.1",
	  "swid": {
		"tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_v0.19.1",
		"name": "cel.dev/expr",
		"version": "v0.19.1"
	  }
    }
  ]
}
`)

var cdxTwoCompWithValidPURLCPESWIDAndSWHID = []byte(`
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
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1",
      "cpe": "cpe:2.3:a:acme:library:3.0:*:*:*:*:go:*:*",
      "swid": {
        "tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_3.0",
        "name": "Acme Library",
        "version": "3.0"
      },
      "swhid": ["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"]
    },
    {
      "bom-ref": "pkg:golang/cel.dev/expr@v0.19.1?type=module",
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
      "purl": "pkg:golang/cel.dev/expr@v0.19.1?type=module\u0026goos=linux\u0026goarch=amd64",
      "cpe": "cpe:/golang/cel.dev/expr:v0.19.1",
      "swid": {
        "tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_v0.19.1",
        "name": "cel.dev/expr",
        "version": "v0.19.1"
      },
	    "swhid": ["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"]
    }
  ]
}
`)

var cdxTwoCompWithValidPURLCPESWIDSWHIDAndOmniborID = []byte(`
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
      "purl": "pkg:golang/github.com/pkg/errors@0.9.1",
      "cpe": "cpe:2.3:a:acme:library:3.0:*:*:*:*:go:*:*",
      "swid": {
        "tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_3.0",
        "name": "Acme Library",
        "version": "3.0"
      },
      "swhid": ["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"],
      "omniborId": ["gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"]
    },
    {
      "bom-ref": "pkg:golang/cel.dev/expr@v0.19.1?type=module",
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
      "purl": "pkg:golang/cel.dev/expr@v0.19.1?type=module\u0026goos=linux\u0026goarch=amd64",
      "cpe": "cpe:/golang/cel.dev/expr:v0.19.1",
      "swid": {
        "tagId": "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_v0.19.1",
        "name": "cel.dev/expr",
        "version": "v0.19.1"
      },
	    "swhid": ["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"],
	    "omniborId": ["gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"]
    }
  ]
}
`)

func TestFSCTCompUniqueIDs(t *testing.T) {
	ctx := context.Background()

	// cdxCompValidPURL
	t.Run("cdxCompValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPURLValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLInValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompInValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompInValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPURLWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxCompPURLWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxCompWithMultiplePURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMultiplePURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (SWID)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// TODO: validate SWID scoring once implemented
	t.Run("cdxCompSWIDInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDInValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (SWID)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	//----
	t.Run("cdxCompSWHIDValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (SWHID)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDInValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// --------
	t.Run("cdxCompOmniborIDValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (OmniborID)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDInValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for all (1) components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithValidPURLAndCPE", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithValidPURLAndCPE, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL, CPE)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithValidPURLCPEAndSWID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithValidPURLCPEAndSWID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL, CPE, SWID)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithValidPURLCPESWIDAndSWHID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithValidPURLCPESWIDAndSWHID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL, CPE, SWHID, SWID)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithValidPURLCPESWIDSWHIDAndOmniborID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithValidPURLCPESWIDSWHIDAndOmniborID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (PURL, CPE, SWHID, SWID, OmniborID)", got.Desc)
		assert.False(t, got.Ignore)
	})

}
