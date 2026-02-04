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

package fsct

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cdxSBOMAuthorWithNameAndEmail = []byte(`
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

var spdxSBOMAuthorWithOrganizationNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization: Samantha Wright (samantha.wright@example.com)"
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

var cdxSBOMAuthorWithEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "bom-ref": "author-1",
        "email": "samantha.wright@example.com"
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorWithPersonEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

var spdxSBOMAuthorWithOrganizationEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization:  (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

var cdxSBOMAuthorWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Samantha Wright"
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorWithPersonName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright"
    ]
  },
  "packages": []
}
`)

var spdxSBOMAuthorWithOrganizationName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization: Samantha Wright"
    ]
  },
  "packages": []
}
`)

var cdxSBOMAuthorsAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMAuthorAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {},
  "packages": []
}
`)

var cdxSBOMAuthorMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": []
  },
  "components": []
}
`)

var spdxSBOMAuthorPersonMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: "
    ]
  },
  "packages": []
}
`)

var spdxSBOMAuthorOrganizationMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization: "
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

var cdxSBOMAuthorsWithEmptyArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "authors": []
  },
  "components": []
}
`)

var cdxSBOMAuthorsWithEmptyArrayObject = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [{}]
  },
  "components": []
}
`)

var spdxSBOMAuthorsWithEmptyArray = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": []
  },
  "packages": []
}
`)

var cdxSBOMAuthorsWithWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": {}
  },
  "components": []
}
`)

var spdxSBOMCreatorsWithWrongTypeSomeValue = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["foobar"]
  },
  "packages": []
}
`)

var spdxSBOMCreatorsWithWhitespace = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["    "]
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

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright (samantha.wright@example.com)", got.CheckValue)
	})

	// spdxSBOMAuthorWithNameAndEmail
	t.Run("spdxSBOMAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright (samantha.wright@example.com)", got.CheckValue)
	})

	// spdxSBOMAuthorWithOrganizationNameAndEmail
	t.Run("spdxSBOMAuthorWithOrganizationNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright (samantha.wright@example.com)", got.CheckValue)
	})

	// cdxSBOMAuthorAndTool
	t.Run("cdxSBOMAuthorAndTool", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorAndTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 12.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Recommended Practice", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright (samantha.wright@example.com) | TOOLS DECLARED: (1) cyclonedx-gomod-v1.9.0", got.CheckValue)
	})

	// spdxSBOMAuthorAndTool
	t.Run("spdxSBOMAuthorAndTool", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAndTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 12.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Recommended Practice", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright (samantha.wright@example.com) | TOOLS DECLARED: (1) cyclonedx-gomod-v1.9.0", got.CheckValue)
	})

	// cdxSBOMMultipleAuthorsWithNameAndEmail
	t.Run("cdxSBOMMultipleAuthorsWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMultipleAuthorsWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Interlynk (hello@interlynk.io, 800-555-1212)(2) VulnCon SBOM Generation Workshop (vulncon@sbom.dev, 800-555-1313)(3) Interlynk (hi@interlynk.io, 800-555-1414)", got.CheckValue)
	})

	// spdxSBOMMultipleAuthorWithNameAndEmail
	t.Run("spdxSBOMMultipleAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMultipleAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Interlynk (hello@interlynk.io, 800-555-1212)(2) VulnCon SBOM Generation Workshop (vulncon@sbom.dev, 800-555-1313)(3) Interlynk (hi@interlynk.io, 800-555-1414)", got.CheckValue)
	})

	// cdxSBOMMultipleAuthorsAndTools
	t.Run("cdxSBOMMultipleAuthorsAndTools", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMultipleAuthorsAndTools, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 12.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Recommended Practice", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Interlynk (hello@interlynk.io, 800-555-1212)(2) VulnCon SBOM Generation Workshop (vulncon@sbom.dev, 800-555-1313)(3) Interlynk (hi@interlynk.io, 800-555-1414) | TOOLS DECLARED: (1) cyclonedx-gomod-v1.9.0", got.CheckValue)
	})

	// spdxSBOMMultipleAuthorsAndTools
	t.Run("spdxSBOMMultipleAuthorsAndTools", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMultipleAuthorsAndTools, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 12.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Recommended Practice", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Interlynk (hello@interlynk.io, 800-555-1212)(2) VulnCon SBOM Generation Workshop (vulncon@sbom.dev, 800-555-1313)(3) Interlynk (hi@interlynk.io, 800-555-1414) | TOOLS DECLARED: (1) cyclonedx-gomod-v1.9.0", got.CheckValue)
	})

	// cdxSBOMAuthorWithEmail
	t.Run("cdxSBOMAuthorWithEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) (samantha.wright@example.com)", got.CheckValue)
	})

	// spdxSBOMAuthorWithPersonEmail
	t.Run("spdxSBOMAuthorWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) (samantha.wright@example.com)", got.CheckValue)
	})

	// spdxSBOMAuthorWithOrganizationEmail
	t.Run("spdxSBOMAuthorWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) (samantha.wright@example.com)", got.CheckValue)
	})

	// cdxSBOMAuthorWithName
	t.Run("cdxSBOMAuthorWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright", got.CheckValue)
	})

	// spdxSBOMAuthorWithPersonName
	t.Run("spdxSBOMAuthorWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright", got.CheckValue)
	})

	// spdxSBOMAuthorWithOrganizationName
	t.Run("spdxSBOMAuthorWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "AUTHORS DECLARED: (1) Samantha Wright", got.CheckValue)
	})

	// cdxSBOMAuthorsAbsent
	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// spdxSBOMAuthorAbsent
	t.Run("spdxSBOMAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// cdxSBOMAuthorMissing
	t.Run("cdxSBOMAuthorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// spdxSBOMAuthorPersonMissing
	t.Run("spdxSBOMAuthorPersonMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorPersonMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// spdxSBOMAuthorOrganizationMissing
	t.Run("spdxSBOMAuthorOrganizationMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorOrganizationMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// cdxSBOMAuthorsWithEmptyString
	t.Run("cdxSBOMAuthorsWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
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

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// cdxSBOMAuthorsWithEmptyArrayObject
	t.Run("cdxSBOMAuthorsWithEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// spdxSBOMAuthorsWithEmptyArray
	t.Run("spdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
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

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})

	// spdxSBOMTool
	t.Run("spdxSBOMAutspdxSBOMToolhorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTHOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Non-Compliant", got.Maturity)
		assert.Equal(t, "SBOM author not declared", got.CheckValue)
	})
}

var cdxSBOMLifecycleBuildType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      {
        "phase": "design"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMLifecycleWithMultipleTypes = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      {
        "phase": "design"
      },
      {
        "phase": "pre-build"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMLifecycleEmpty = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [ ]
  },
  "components": []
}
`)

var cdxSBOMLifecycleAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

func TestFSCTSBOMLifecycle(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMLifecycleBuildType
	t.Run("cdxSBOMLifecycleBuildType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifecycleBuildType, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMType(doc)

		assert.InDelta(t, 15.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TYPE, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Aspirational", got.Maturity)
		assert.Equal(t, "design", got.CheckValue)
	})

	// cdxSBOMLifecycleWithMultipleTypes
	t.Run("cdxSBOMLifecycleWithMultipleTypes", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifecycleWithMultipleTypes, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMType(doc)

		assert.InDelta(t, 15.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TYPE, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Aspirational", got.Maturity)
		assert.Equal(t, "design, pre-build", got.CheckValue)
	})

	// cdxSBOMLifecycleEmpty
	t.Run("cdxSBOMLifecycleEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifecycleEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMType(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TYPE, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "SBOM type not declared; optional per FSCT", got.CheckValue)
	})

	// cdxSBOMLifecycleWithMultipleTypes
	t.Run("cdxSBOMLifecycleWithMultipleTypes", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifecycleWithMultipleTypes, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMType(doc)

		assert.InDelta(t, 15.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TYPE, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Aspirational", got.Maturity)
		assert.Equal(t, "design, pre-build", got.CheckValue)
	})
}

var cdxCompSupplierWithNameURLAndEmail = []byte(`
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
        ],
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

var spdxCompSupplierAsPersonWithNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Person: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var spdxCompSupplierAsOrganizationWithNameAndEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Organization: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

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

var spdxCompSupplierWithPersonEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Person: (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var spdxCompSupplierWithOrganizationEmail = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Organization:  (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var cdxCompSupplierWithName = []byte(`
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
        "name": "Acme, Inc."
      }
    }
	
  ]
}
`)

var spdxCompSupplierWithPersonName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Person: Samantha Wright",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var spdxCompSupplierWithOrganizationName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Organization: Samantha Wright",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
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

var cdxCompSupplierAbsent = []byte(`
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

var spdxCompSupplierAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person:  (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var cdxCompManufacturerWithNameURLAndEmail = []byte(`
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
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ],
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

var cdxCompSupplierWithEmptyName = []byte(`
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
        "name": ""
      }
    }
  ]
}
`)

var spdxCompSupplierWithPersonNameEmpty = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person:  (samantha.wright@example.com)"
    ]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
      "supplier": "Person:  ( )",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var cdxCompSupplierWithWhiteSpaceName = []byte(`
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
        "name": "  "
      }
    }
  ]
}
`)

func TestFSCTCompSupplier(t *testing.T) {
	ctx := context.Background()
	t.Run("cdxCompSupplierWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "Acme, Inc., https://example.com, (Acme Professional Services, professional.services@example.com)", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierAsPersonWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsPersonWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "Samantha Wright, samantha.wright@example.com", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierAsOrganizationWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsOrganizationWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "Samantha Wright, samantha.wright@example.com", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithNameURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "Acme, Inc., https://example.com", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "samantha.wright@example.com", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "samantha.wright@example.com", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "Acme, Inc.", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "Samantha Wright", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "Samantha Wright", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "https://example.com", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithContactNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithContactNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "(Acme Professional Services, professional.services@example.com)", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithContactName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithContactName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "(Acme Professional Services)", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithContactEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithContactEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "(professional.services@example.com)", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component supplier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component supplier not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component supplier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompManufacturerWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component supplier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component supplier not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompSupplierWithPersonNameEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component supplier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSupplierWithWhiteSpaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithWhiteSpaceName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompSupplier(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SUPPLIER, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component supplier not declared", got.CheckValue)
		}
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

var cdxCompWithValidLargePURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "github.com/Azure/azure-sdk-for-go/sdk/azcore",
      "version": "v1.17.0",
      "purl": "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0?type=module\u0026goos=linux\u0026goarch=amd64"
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
      "swhid": ["   "]

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

func TestFSCTCompUniqueIDs(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidPURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "pkg:golang/github.com/pkg/errors@0.9.1", got.CheckValue)
		}
	})

	t.Run("cdxCompWithValidLargePURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithValidLargePURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0?type=module&goos=linux&goarch=amd64", got.CheckValue)
		}
	})

	t.Run("spdxCompPURLValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "pkg:golang/github.com/pkg/errors@0.9.1", got.CheckValue)
		}
	})

	t.Run("cdxCompPURLInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLInValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompInValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompInValidPURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompPURLWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompPURLWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
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

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.17.0?type=module, pkg:golang/github.com/A\nzure/azure-sdk-for-go/sdk/azcore@v1.17.0?type=module&goos=linux&goarch=amd64", got.CheckValue)
		}
	})

	t.Run("cdxCompSWIDValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1", got.CheckValue)
		}
	})

	// TODO: validate SWID tagId format more strictly
	t.Run("cdxCompSWIDInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDInValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "slkjj82398jwwAKL;LKCNMC", got.CheckValue)
		}
	})

	t.Run("cdxCompSWIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWHIDValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2", got.CheckValue)
		}
	})

	// TODO: validate SWID tagId format more strictly
	t.Run("cdxCompSWHIDInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDInValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWHIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWHIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWHIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompSWHIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	// -----------
	t.Run("cdxCompOmniborIDValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", got.CheckValue)
		}
	})

	// TODO: invalid OmniBorID is not counted, therefore test will pass
	t.Run("cdxCompOmniborIDInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDInValid, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompOmniborIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompOmniborIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompOmniborIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompOmniborIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompUniqIDs(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component unique identifier not declared", got.CheckValue)
		}
	})
}

var cdxCompWithMixValidChecksums = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-example",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "MD5",
          "content": "641b6e166f8b33c5e959e2adcc18b1c7"
        },
        {
          "alg": "SHA-1",
          "content": "9188560f22e0b73070d2efce670c74af2bdf30af"
        },
        {
          "alg": "SHA-256",
          "content": "d88bc4e70bfb34d18b5542136639acbb26a8ae2429aa1e47489332fb389cc964"
        },
        {
          "alg": "SHA-512",
          "content": "74a51ff45e4c11df9ba1f0094282c80489649cb157a75fa337992d2d4592a5a1b8cb4525de8db0ae25233553924d76c36e093ea7fa9df4e5b8b07fd2e074efd6"
        }
      ]
    }
  ]
}
`)

var spdxCompWithMixValidChecksums = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme-example",
      "versionInfo": "1.0.0",
      "checksums": [
        {
          "algorithm": "MD5",
          "checksumValue": "641b6e166f8b33c5e959e2adcc18b1c7"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "9188560f22e0b73070d2efce670c74af2bdf30af"
        },
        {
          "algorithm": "SHA256",
          "checksumValue": "d88bc4e70bfb34d18b5542136639acbb26a8ae2429aa1e47489332fb389cc964"
        },
        {
          "algorithm": "SHA512",
          "checksumValue": "74a51ff45e4c11df9ba1f0094282c80489649cb157a75fa337992d2d4592a5a1b8cb4525de8db0ae25233553924d76c36e093ea7fa9df4e5b8b07fd2e074efd6"
        }
      ]
    }
  ]
}
`)

var cdxCompChecksumWeak = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-example",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "MD5",
          "content": "641b6e166f8b33c5e959e2adcc18b1c7"
        },
        {
          "alg": "SHA-1",
          "content": "9188560f22e0b73070d2efce670c74af2bdf30af"
        }
      ]
    }
  ]
}
`)

var spdxCompChecksumWeak = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme-example",
      "versionInfo": "1.0.0",
      "checksums": [
        {
          "algorithm": "MD5",
          "checksumValue": "641b6e166f8b33c5e959e2adcc18b1c7"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "9188560f22e0b73070d2efce670c74af2bdf30af"
        }
      ]
    }
  ]
}
`)

var cdxCompChecksumStrong = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-example",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "d88bc4e70bfb34d18b5542136639acbb26a8ae2429aa1e47489332fb389cc964"
        },
        {
          "alg": "SHA-512",
          "content": "74a51ff45e4c11df9ba1f0094282c80489649cb157a75fa337992d2d4592a5a1b8cb4525de8db0ae25233553924d76c36e093ea7fa9df4e5b8b07fd2e074efd6"
        }
      ]
    }
  ]
}
`)

var spdxCompChecksumStrong = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme-example",
      "versionInfo": "1.0.0",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "d88bc4e70bfb34d18b5542136639acbb26a8ae2429aa1e47489332fb389cc964"
        },
        {
          "algorithm": "SHA512",
          "checksumValue": "74a51ff45e4c11df9ba1f0094282c80489649cb157a75fa337992d2d4592a5a1b8cb4525de8db0ae25233553924d76c36e093ea7fa9df4e5b8b07fd2e074efd6"
        }
      ]
    }
  ]
}
`)

var cdxCompChecksumWithEmptyValue = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-example",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": ""
        }
      ]
    }
  ]
}
`)

var spdxCompChecksumWithEmptyValue = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme-example",
      "versionInfo": "1.0.0",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": ""
        }
      ]
    }
  ]
}
`)

var cdxCompChecksumMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-example",
      "version": "1.0.0",
      "hashes": []
    }
  ]
}
`)

var spdxCompChecksumMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme-example",
      "versionInfo": "1.0.0",
      "checksums": []
    }
  ]
}
`)

var cdxCompChecksumAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-example",
      "version": "1.0.0"
    }
  ]
}
`)

var spdxCompChecksumAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme-example",
      "versionInfo": "1.0.0"
    }
  ]
}
`)

var cdxCompChecksumPresentAndMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-example",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "d88bc4e70bfb34d18b5542136639acbb26a8ae2429aa1e47489332fb389cc964"
        },
        {
          "alg": "SHA-512",
          "content": ""
        }
      ]
    }
  ]
}
`)

var spdxCompChecksumPresentAndMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme-example",
      "versionInfo": "1.0.0",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "d88bc4e70bfb34d18b5542136639acbb26a8ae2429aa1e47489332fb389cc964"
        },
        {
          "algorithm": "SHA512",
          "checksumValue": ""
        }
      ]
    }
  ]
}
`)

func TestFSCTCompChecksums(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 12.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Recommended Practice", got.Maturity)
			assert.Equal(t, "MD5, SHA1, SHA256, SHA512", got.CheckValue)
		}
	})

	t.Run("spdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 12.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Recommended Practice", got.Maturity)
			assert.Equal(t, "MD5, SHA1, SHA256, SHA512", got.CheckValue)
		}
	})

	t.Run("cdxCompChecksumWeak", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumWeak, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "MD5, SHA1", got.CheckValue)
		}
	})

	t.Run("spdxCompChecksumWeak", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumWeak, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "MD5, SHA1", got.CheckValue)
		}
	})

	t.Run("cdxCompChecksumStrong", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumStrong, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 12.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Recommended Practice", got.Maturity)
			assert.Equal(t, "SHA256, SHA512", got.CheckValue)
		}
	})

	t.Run("spdxCompChecksumStrong", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumStrong, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 12.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Recommended Practice", got.Maturity)
			assert.Equal(t, "SHA256, SHA512", got.CheckValue)
		}
	})

	t.Run("cdxCompChecksumWithEmptyValue", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumWithEmptyValue, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component checksum not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompChecksumWithEmptyValue", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumWithEmptyValue, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component checksum not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompChecksumMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component checksum not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompChecksumMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component checksum not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompChecksumAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component checksum not declared", got.CheckValue)
		}
	})

	t.Run("spdxCompChecksumAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Non-Compliant", got.Maturity)
			assert.Equal(t, "Component checksum not declared", got.CheckValue)
		}
	})

	t.Run("cdxCompChecksumPresentAndMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumPresentAndMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 12.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Recommended Practice", got.Maturity)
			assert.Equal(t, "SHA256", got.CheckValue)
		}
	})

	t.Run("spdxCompChecksumPresentAndMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumPresentAndMissing, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {

			got := fsctCompChecksum(c)

			assert.InDelta(t, 12.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CHECKSUM, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Recommended Practice", got.Maturity)
			assert.Equal(t, "SHA256", got.CheckValue)
		}
	})
}

var cdxDepsWithPrimaryCompletenessAndAllComponentCompleteness = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },

  "components": [
    {
      "bom-ref": "pkg:generic/lib-a@2.1.0",
      "type": "library",
      "name": "lib-a",
      "version": "2.1.0"
    },
    {
      "bom-ref": "pkg:generic/lib-b@3.4.5",
      "type": "library",
      "name": "lib-b",
      "version": "3.4.5"
    },
    {
      "bom-ref": "pkg:generic/lib-c@4.1.3",
      "type": "library",
      "name": "lib-c",
      "version": "4.1.3"
    }
  ],

  "dependencies": [
    {
      "ref": "pkg:generic/my-app@1.0.0",
      "dependsOn": [
        "pkg:generic/lib-a@2.1.0",
        "pkg:generic/lib-b@3.4.5"
      ]
    },
    {
      "ref": "pkg:generic/lib-a@2.1.0",
      "dependsOn": []
    },
    {
      "ref": "pkg:generic/lib-b@3.4.5",
      "dependsOn": [
        "pkg:generic/lib-c@4.1.3"
      ]
    },
    {
      "ref": "pkg:generic/lib-c@4.1.3",
      "dependsOn": []
    }
  ],

  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/my-app@1.0.0"
      ]
    },
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-a@2.1.0"
      ]
    },
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-b@3.4.5"
      ]
    },
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-c@4.1.3"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessAndBothDirectDepsCompleteness = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },

  "components": [
    {
      "bom-ref": "pkg:generic/lib-a@2.1.0",
      "type": "library",
      "name": "lib-a",
      "version": "2.1.0"
    },
    {
      "bom-ref": "pkg:generic/lib-b@3.4.5",
      "type": "library",
      "name": "lib-b",
      "version": "3.4.5"
    },
    {
      "bom-ref": "pkg:generic/lib-c@4.1.3",
      "type": "library",
      "name": "lib-c",
      "version": "4.1.3"
    }
  ],

  "dependencies": [
    {
      "ref": "pkg:generic/my-app@1.0.0",
      "dependsOn": [
        "pkg:generic/lib-a@2.1.0",
        "pkg:generic/lib-b@3.4.5"
      ]
    },
    {
      "ref": "pkg:generic/lib-a@2.1.0",
      "dependsOn": []
    },
    {
      "ref": "pkg:generic/lib-b@3.4.5",
      "dependsOn": [
        "pkg:generic/lib-c@4.1.3"
      ]
    },
    {
      "ref": "pkg:generic/lib-c@4.1.3",
      "dependsOn": []
    }
  ],

  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/my-app@1.0.0"
      ]
    },
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-a@2.1.0"
      ]
    },
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-b@3.4.5"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessAndOneDirectDepMissingCompleteness = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },

  "components": [
    {
      "bom-ref": "pkg:generic/lib-a@2.1.0",
      "type": "library",
      "name": "lib-a",
      "version": "2.1.0"
    },
    {
      "bom-ref": "pkg:generic/lib-b@3.4.5",
      "type": "library",
      "name": "lib-b",
      "version": "3.4.5"
    },
    {
      "bom-ref": "pkg:generic/lib-c@4.1.3",
      "type": "library",
      "name": "lib-c",
      "version": "4.1.3"
    }
  ],

  "dependencies": [
    {
      "ref": "pkg:generic/my-app@1.0.0",
      "dependsOn": [
        "pkg:generic/lib-a@2.1.0",
        "pkg:generic/lib-b@3.4.5"
      ]
    },
    {
      "ref": "pkg:generic/lib-a@2.1.0",
      "dependsOn": []
    },
    {
      "ref": "pkg:generic/lib-b@3.4.5",
      "dependsOn": [
        "pkg:generic/lib-c@4.1.3"
      ]
    },
    {
      "ref": "pkg:generic/lib-c@4.1.3",
      "dependsOn": []
    }
  ],

  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/my-app@1.0.0"
      ]
    },
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-a@2.1.0"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },

  "components": [
    {
      "bom-ref": "pkg:generic/lib-a@2.1.0",
      "type": "library",
      "name": "lib-a",
      "version": "2.1.0"
    },
    {
      "bom-ref": "pkg:generic/lib-b@3.4.5",
      "type": "library",
      "name": "lib-b",
      "version": "3.4.5"
    }
  ],

  "dependencies": [
    {
      "ref": "pkg:generic/my-app@1.0.0",
      "dependsOn": [
        "pkg:generic/lib-a@2.1.0",
        "pkg:generic/lib-b@3.4.5"
      ]
    },
    {
      "ref": "pkg:generic/lib-a@2.1.0",
      "dependsOn": []
    },
    {
      "ref": "pkg:generic/lib-b@3.4.5",
      "dependsOn": []
    }
  ],

  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-a@2.1.0"
      ]
    },
    {
      "aggregate": "complete",
      "dependencies": [
        "pkg:generic/lib-b@3.4.5"
      ]
    }
  ]
}
`)

func TestFSCTSBOMRelationships(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxDepsWithPrimaryCompletenessAndAllComponentCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessAndAllComponentCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 12.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_RELATIONSHIPS, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Recommended Practice", got.Maturity)
		assert.Equal(t, "relationships and completeness declared for all included components", got.CheckValue)
	})

	t.Run("cdxDepsWithPrimaryCompletenessAndBothDirectDepsCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessAndBothDirectDepsCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_RELATIONSHIPS, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "relationships and completeness explicitly declared for primary component and direct dependencies", got.CheckValue)
	})

	t.Run("cdxDepsWithPrimaryCompletenessAndOneDirectDepMissingCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessAndOneDirectDepMissingCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_RELATIONSHIPS, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "None", got.Maturity)
		assert.Equal(t, "dependency completeness missing for 1 of 2 direct dependencies", got.CheckValue)
	})

	t.Run("cdxDepsWithPrimaryCompletenessMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_RELATIONSHIPS, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "None", got.Maturity)
		assert.Equal(t, "dependency relationship(2), but dependency completeness missing for primary component", got.CheckValue)
	})
}
