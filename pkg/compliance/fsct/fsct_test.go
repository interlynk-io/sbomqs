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
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/swhid"
	"github.com/interlynk-io/sbomqs/v2/pkg/swid"
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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMAuthor(doc)

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

		got := SBOMType(doc)

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

		got := SBOMType(doc)

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

		got := SBOMType(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TYPE, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "Minimum Expected", got.Maturity)
		assert.Equal(t, "SBOM type not declared", got.CheckValue)
	})

	// cdxSBOMLifecycleWithMultipleTypes
	t.Run("cdxSBOMLifecycleWithMultipleTypes", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifecycleWithMultipleTypes, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMType(doc)

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
      "swid": {
        "tagId": "slkjj82398jwwAKL;LKCNMC",
        "name": "Acme Application",
        "version": "9.1.1"
      }
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
      "swid": {
        "tagId": "",
        "name": "Acme Application",
        "version": "9.1.1"
      }
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
      "swid": {}
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
      "swid": {
        "tagId": "    "
      }
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

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_UNIQ_ID, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Minimum Expected", got.Maturity)
			assert.Equal(t, "slkjj82398jwwAKL;LKCNMC", got.CheckValue)
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

type desired struct {
	score    float64
	result   string
	key      int
	id       string
	maturity string
}

func cdxDocWithSbomAuthorNameEmailAndContact() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	author.Email = "samantha.wright@example.com"
	author.Phone = "800-555-1212"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithSbomAuthorNameAndEmail() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	author.Email = "samantha.wright@example.com"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithSbomAuthorNameAndContact() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.Phone = "800-555-1212"
	author.AuthorType = "person"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithSbomAuthorName() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithTool() sbom.Document {
	tools := []sbom.GetTool{}
	tool := sbom.Tool{}
	tool.Name = "sbom-tool"
	tool.Version = "9.1.2"
	tools = append(tools, tool)

	doc := sbom.CdxDoc{
		CdxTools: tools,
	}
	return doc
}

func cdxDocWithMultipleTools() sbom.Document {
	tools := []sbom.GetTool{}
	componentTool := sbom.Tool{}
	componentTool.Name = "sbom-tool"
	componentTool.Version = "9.1.2"
	tools = append(tools, componentTool)

	serviceTool := sbom.Tool{}
	serviceTool.Name = "syft"
	serviceTool.Version = "1.1.2"
	tools = append(tools, serviceTool)

	doc := sbom.CdxDoc{
		CdxTools: tools,
	}
	return doc
}

func cdxDocWithAuthorAndTools() sbom.Document {
	tools := []sbom.GetTool{}
	tool := sbom.Tool{}
	tool.Name = "sbom-tool"
	tool.Version = "9.1.2"
	tools = append(tools, tool)

	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	author.Email = "samantha.wright@example.com"
	author.Phone = "800-555-1212"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
		CdxTools:   tools,
	}
	return doc
}

func TestFsctCDXSbomAuthorFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "CDX SBOM with author name only",
			actual: SBOMAuthor(cdxDocWithSbomAuthorName()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with author name and email",
			actual: SBOMAuthor(cdxDocWithSbomAuthorNameAndEmail()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright (samantha.wright@example.com)",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with author name and contact",
			actual: SBOMAuthor(cdxDocWithSbomAuthorNameAndContact()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright (800-555-1212)",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with author name, email and contact",
			actual: SBOMAuthor(cdxDocWithSbomAuthorNameEmailAndContact()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright (samantha.wright@example.com, 800-555-1212)",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with a tool",
			actual: SBOMAuthor(cdxDocWithTool()),
			expected: desired{
				score:    0.0,
				result:   "sbom-tool-9.1.2",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "None",
			},
		},
		{
			name:   "CDX SBOM with multiple tools",
			actual: SBOMAuthor(cdxDocWithMultipleTools()),
			expected: desired{
				score:    0.0,
				result:   "sbom-tool-9.1.2, syft-1.1.2",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "None",
			},
		},
		{
			name:   "CDX SBOM with a Author and tool",
			actual: SBOMAuthor(cdxDocWithAuthorAndTools()),
			expected: desired{
				score:    12.0,
				result:   "Samantha Wright (samantha.wright@example.com, 800-555-1212), sbom-tool-9.1.2",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Recommended",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

func cdxDocWithPrimaryComponent() sbom.Document {
	primary := sbom.PrimaryComponentInfo{}
	primary.ID = "pkg:git@github.com:interlynk/sbomqs.git"
	primary.Name = "interlynk-io/sbomqs"
	primary.Version = "v0.0.3"
	primary.Type = "application"
	primary.Present = true

	doc := sbom.CdxDoc{
		PrimaryComponent: primary,
	}
	return doc
}

func cdxDocWithPreDefinedPhaseLifecycles() sbom.Document {
	phase := "build"

	doc := sbom.SpdxDoc{
		Lifecycle: phase,
	}
	return doc
}

func cdxDocWithCustomPhaseLifecycles() sbom.Document {
	name := "platform-integration-testing"
	// description := "Integration testing specific to the runtime platform"
	doc := sbom.SpdxDoc{
		Lifecycle: name,
	}
	return doc
}

func cdxDocWithTimestamp() sbom.Document {
	s := sbom.NewSpec()
	s.CreationTimestamp = "2020-04-13T20:20:39+00:00"
	doc := sbom.CdxDoc{
		CdxSpec: s,
	}
	return doc
}

func TestFsctCDXOtherSbomLevelFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "CDX SBOM with timestamp",
			actual: SBOMTimestamp(cdxDocWithTimestamp()),
			expected: desired{
				score:    10.0,
				result:   "2020-04-13T20:20:39+00:00",
				key:      SBOM_TIMESTAMP,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with custom phase lifecycle",
			actual: SBOMType(cdxDocWithCustomPhaseLifecycles()),
			expected: desired{
				score:    15.0,
				result:   "platform-integration-testing",
				key:      SBOM_TYPE,
				id:       "doc",
				maturity: "Aspirational",
			},
		},
		{
			name:   "CDX SBOM with pre-defined phase lifecycle",
			actual: SBOMType(cdxDocWithPreDefinedPhaseLifecycles()),
			expected: desired{
				score:    15.0,
				result:   "build",
				key:      SBOM_TYPE,
				id:       "doc",
				maturity: "Aspirational",
			},
		},
		{
			name:   "CDX SBOM with primary component",
			actual: SBOMPrimaryComponent(cdxDocWithPrimaryComponent()),
			expected: desired{
				score:    10.0,
				result:   "interlynk-io/sbomqs",
				key:      SBOM_PRIMARY_COMPONENT,
				id:       "doc",
				maturity: "Minimum",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

func spdxDocWithSbomAuthor() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}

	author.Name = "Jane Doe"

	author.AuthorType = "person"
	authors = append(authors, author)

	doc := sbom.SpdxDoc{
		Auths: authors,
	}
	return doc
}

func spdxDocWithSbomAuthorAndTool() sbom.Document {
	authors := []sbom.GetAuthor{}
	tools := []sbom.GetTool{}

	tool := sbom.Tool{}
	author := sbom.Author{}
	author.Name = "Jane Doe"
	tool.Name = "syft"
	tool.Version = "1.9.0"

	author.AuthorType = "person"
	authors = append(authors, author)
	tools = append(tools, tool)

	doc := sbom.SpdxDoc{
		Auths:     authors,
		SpdxTools: tools,
	}
	return doc
}

func spdxDocWithSbomTool() sbom.Document {
	tools := []sbom.GetTool{}

	tool := sbom.Tool{}
	tool.Name = "syft"
	tool.Version = "1.9.0"

	tools = append(tools, tool)

	doc := sbom.SpdxDoc{
		SpdxTools: tools,
	}
	return doc
}

func spdxDocWithLifecycles() sbom.Document {
	creatorComment := "hellow, this is sbom build phase"

	doc := sbom.SpdxDoc{
		Lifecycle: creatorComment,
	}
	return doc
}

func spdxDocWithPrimaryComponent() sbom.Document {
	primary := sbom.PrimaryComponentInfo{}

	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"
	primary.Name = "sbomqs-linux-amd64"
	primary.Version = "v0.0.3"
	primary.Type = "application"
	primary.Present = true

	doc := sbom.CdxDoc{
		PrimaryComponent: primary,
	}
	return doc
}

func TestFsctSPDXSbomLevelFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "SPDX SBOM with lifecycle",
			actual: SBOMType(spdxDocWithLifecycles()),
			expected: desired{
				score:    15.0,
				result:   "hellow, this is sbom build phase",
				key:      SBOM_TYPE,
				id:       "doc",
				maturity: "Aspirational",
			},
		},
		{
			name:   "SPDX SBOM with primary component",
			actual: SBOMPrimaryComponent(spdxDocWithPrimaryComponent()),
			expected: desired{
				score:    10.0,
				result:   "sbomqs-linux-amd64",
				key:      SBOM_PRIMARY_COMPONENT,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX SBOM with author name only",
			actual: SBOMAuthor(spdxDocWithSbomAuthor()),
			expected: desired{
				score:    10.0,
				result:   "Jane Doe",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX SBOM with tool only",
			actual: SBOMAuthor(spdxDocWithSbomTool()),
			expected: desired{
				score:    0.0,
				result:   "syft-1.9.0",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "None",
			},
		},
		{
			name:   "SPDX SBOM with Author and tool both",
			actual: SBOMAuthor(spdxDocWithSbomAuthorAndTool()),
			expected: desired{
				score:    12.0,
				result:   "Jane Doe, syft-1.9.0",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Recommended",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

// COMPONENT LEVEL CHECKS

func compWithName() sbom.GetComponent {
	name := "github.com/google/uuid"

	comp := sbom.Component{
		Name: name,
	}
	return comp
}

func compWithVersion() sbom.GetComponent {
	name := "github.com/google/uuid"
	version := "v1.6.0"

	comp := sbom.Component{
		Name:    name,
		Version: version,
	}
	return comp
}

func spdxCompWithSupplierName() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Name = "Jane Doe"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func spdxCompWithSupplierEmail() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Email = "jane.doe@example.com"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func spdxCompWithSupplierNameAndEmail() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Email = "jane.doe@example.com"
	supp.Name = "Jane Doe"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierName() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Name = "Acme, Inc"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierURL() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.URL = "https://example.com"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierNameAndURL() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Name = "Acme, Inc"
	supp.URL = "https://example.com"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierContactInfo() sbom.GetComponent {
	name := "github.com/google/uuid"

	supp := sbom.Supplier{}
	contact := sbom.Contact{}

	contact.Name = "Acme Distribution"
	contact.Email = "distribution@example.com"
	supp.Contacts = []sbom.Contact{contact}

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierAndContactInfo() sbom.GetComponent {
	name := "github.com/google/uuid"

	supp := sbom.Supplier{}
	supp.Name = "Acme, Inc"
	supp.URL = "https://example.com"

	contact := sbom.Contact{}
	contact.Name = "Acme Distribution"
	contact.Email = "distribution@example.com"
	supp.Contacts = []sbom.Contact{contact}

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func compWithSmallContentCopyright() sbom.GetComponent {
	copyright := "2013-2023 The Cobra Authors"
	comp := sbom.NewComponent()
	comp.CopyRight = copyright
	comp.Name = "cobra"
	comp.Spdxid = "pkg:github/spf13/cobra@e94f6d0dd9a5e5738dca6bce03c4b1207ffbc0ec"

	return comp
}

func compWithBigContentCopyright() sbom.GetComponent {
	copyright := "2014 Sam Ghods\n staring in 2011 when the project was ported over:\n2006-2010 Kirill Simonov\n2006-2011 Kirill Simonov\n2011-2019 Canonical Ltd\n2012 The Go Authors. All rights reserved.\n2006 Kirill Simonov"
	comp := sbom.NewComponent()
	comp.CopyRight = copyright
	comp.Name = "yaml"
	comp.Spdxid = "pkg:github/kubernetes-sigs/yaml@c3772b51db126345efe2dfe4ff8dac83b8141684"

	return comp
}

func compWithNoAssertion() sbom.GetComponent {
	copyright := "NOASSERTION"
	comp := sbom.NewComponent()
	comp.CopyRight = copyright
	comp.Name = "yaml.v2"
	comp.Spdxid = "pkg:golang/gopkg.in/yaml.v2@v2.4.0"

	return comp
}

func TestFsctComponentLevelOnSpdxAndCdx(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "Comp with Name",
			actual: fsctCompName(compWithName()),
			expected: desired{
				score:    10.0,
				result:   "github.com/google/uuid",
				key:      COMP_NAME,
				id:       common.UniqueElementID(compWithName()),
				maturity: "Minimum",
			},
		},
		{
			name:   "Comp with Version",
			actual: fsctCompVersion(compWithVersion()),
			expected: desired{
				score:    10.0,
				result:   "v1.6.0",
				key:      COMP_VERSION,
				id:       common.UniqueElementID(compWithVersion()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with Supplier Name only",
			actual: fsctCompSupplier(spdxCompWithSupplierName()),
			expected: desired{
				score:    10.0,
				result:   "Jane Doe",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(spdxCompWithSupplierName()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with Supplier Email",
			actual: fsctCompSupplier(spdxCompWithSupplierEmail()),
			expected: desired{
				score:    10.0,
				result:   "jane.doe@example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(spdxCompWithSupplierEmail()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with Supplier Name and Email",
			actual: fsctCompSupplier(spdxCompWithSupplierNameAndEmail()),
			expected: desired{
				score:    10.0,
				result:   "Jane Doe, jane.doe@example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(spdxCompWithSupplierNameAndEmail()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier Name",
			actual: fsctCompSupplier(cdxCompWithSupplierName()),
			expected: desired{
				score:    10.0,
				result:   "Acme, Inc",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierName()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier URL",
			actual: fsctCompSupplier(cdxCompWithSupplierURL()),
			expected: desired{
				score:    10.0,
				result:   "https://example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierURL()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier Name and URL",
			actual: fsctCompSupplier(cdxCompWithSupplierNameAndURL()),
			expected: desired{
				score:    10.0,
				result:   "Acme, Inc, https://example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierNameAndURL()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier Contact Info Only",
			actual: fsctCompSupplier(cdxCompWithSupplierContactInfo()),
			expected: desired{
				score:    10.0,
				result:   "(Acme Distribution, distribution@example.com)",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierContactInfo()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier and Contact Info",
			actual: fsctCompSupplier(cdxCompWithSupplierAndContactInfo()),
			expected: desired{
				score:    10.0,
				result:   "Acme, Inc, https://example.com, (Acme Distribution, distribution@example.com)",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierAndContactInfo()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with small content copyright",
			actual: fsctCompCopyright(compWithSmallContentCopyright()),
			expected: desired{
				score:    10.0,
				result:   "2013-2023 The Cobra Authors",
				key:      COMP_COPYRIGHT,
				id:       common.UniqueElementID(compWithSmallContentCopyright()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with small content copyright",
			actual: fsctCompCopyright(compWithBigContentCopyright()),
			expected: desired{
				score:    10.0,
				result:   "2014 Sam Ghods\n staring in 2011 when the project w...",
				key:      COMP_COPYRIGHT,
				id:       common.UniqueElementID(compWithBigContentCopyright()),
				maturity: "Minimum",
			},
		},
		{
			name:   "spdxCompWithNoAssertionCopyright",
			actual: fsctCompCopyright(compWithNoAssertion()),
			expected: desired{
				score:    0.0,
				result:   "",
				key:      COMP_COPYRIGHT,
				id:       common.UniqueElementID(compWithNoAssertion()),
				maturity: "None",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

func primaryCompWithHigherChecksum() (sbom.Document, sbom.GetComponent) {
	primary := sbom.PrimaryComponentInfo{}

	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"
	primary.Name = "sbomqs-linux-amd64"
	primary.Version = "v0.0.3"
	primary.Type = "application"
	primary.Present = true

	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "SHA256"
	ck1.Content = "11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "DocumentRoot-File-sbomqs-linux-amd64",
		Name:      "sbomqs-linux-amd64",
		Checksums: chks,
	}

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
	}

	return doc, comp
}

func primaryCompWithLowerChecksum() (sbom.Document, sbom.GetComponent) {

	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "MD5"
	ck1.Content = "624c1abb3664f4b35547e7c73864ad24"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "DocumentRoot-File-sbomqs-linux-amd64",
		Name:      "sbomqs-linux-amd64",
		Checksums: chks,
	}

	primary := sbom.PrimaryComponentInfo{}

	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"
	primary.Name = "sbomqs-linux-amd64"
	primary.Version = "v0.0.3"
	primary.Type = "application"
	primary.Present = true

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
	}

	return doc, comp
}

func compWithHigherChecksum() (sbom.Document, sbom.GetComponent) {
	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "SHA256"
	ck1.Content = "11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "SPDXRef-Package-go-module-stdlib-2dfa88209de0bd8b",
		Name:      "stdlib",
		Checksums: chks,
	}

	primary := sbom.PrimaryComponentInfo{}

	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"
	primary.Name = "sbomqs-linux-amd64"
	primary.Version = "v0.0.3"
	primary.Type = "application"
	primary.Present = true

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
	}
	return doc, comp
}

func compWithLowerChecksum() (sbom.Document, sbom.GetComponent) {
	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "MD5"
	ck1.Content = "624c1abb3664f4b35547e7c73864ad24"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "SPDXRef-Package-go-module-stdlib-2dfa88209de0bd8b",
		Name:      "stdlib",
		Checksums: chks,
	}

	primary := sbom.PrimaryComponentInfo{}

	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"
	primary.Name = "sbomqs-linux-amd64"
	primary.Version = "v0.0.3"
	primary.Type = "application"
	primary.Present = true

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
	}
	return &doc, comp
}

// func TestFsctChecksums(t *testing.T) {
// 	_, pch := primaryCompWithHigherChecksum()
// 	_, pcl := primaryCompWithLowerChecksum()
// 	_, nch := compWithHigherChecksum()
// 	_, ncl := compWithLowerChecksum()
// 	testCases := []struct {
// 		name     string
// 		actual   *db.Record
// 		expected desired
// 	}{
// 		{
// 			name:   "SPDX primary Comp with higher Checksum",
// 			actual: fsctCompChecksum(primaryCompWithHigherChecksum()),
// 			expected: desired{
// 				score:    12.0,
// 				result:   "SHA256, SHA1",
// 				key:      COMP_CHECKSUM,
// 				id:       common.UniqueElementID(pch),
// 				maturity: "Recommended",
// 			},
// 		},
// 		{
// 			name:   "SPDX primary Comp with lower Checksum",
// 			actual: fsctCompChecksum(primaryCompWithLowerChecksum()),
// 			expected: desired{
// 				score:    10.0,
// 				result:   "MD5, SHA1",
// 				key:      COMP_CHECKSUM,
// 				id:       common.UniqueElementID(pcl),
// 				maturity: "Minimum",
// 			},
// 		},
// 		{
// 			name:   "SPDX Comp with higher Checksum",
// 			actual: fsctCompChecksum(compWithHigherChecksum()),
// 			expected: desired{
// 				score:    10.0,
// 				result:   "SHA256, SHA1",
// 				key:      COMP_CHECKSUM,
// 				id:       common.UniqueElementID(nch),
// 				maturity: "Minimum",
// 			},
// 		},
// 		{
// 			name:   "SPDX Comp with lower Checksum",
// 			actual: fsctCompChecksum(compWithLowerChecksum()),
// 			expected: desired{
// 				score:    10.0,
// 				result:   "MD5, SHA1",
// 				key:      COMP_CHECKSUM,
// 				id:       common.UniqueElementID(ncl),
// 				maturity: "Minimum",
// 			},
// 		},
// 	}
// 	for _, test := range testCases {
// 		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
// 	}
// }

type ElementRefID struct {
	ID string
}
type Relationship struct {
	Relationship string
	RefA         ElementRefID
	RefB         ElementRefID
}

func cdxCompIsPartOfPrimaryCompDependency() sbom.Document {

	comp1 := sbom.Component{}
	comp1.ID = "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	comp1.Name = "sbomqs-linux-amd64"
	comp1.Version = "v1.0.0"

	comp2 := sbom.Component{}
	comp2.ID = "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"
	comp2.Name = "go-github"
	comp2.Version = "v2.0.0"

	primary := sbom.PrimaryComponentInfo{}

	primary.ID = comp1.ID
	primary.Name = comp1.Name
	primary.Version = comp1.Version
	primary.Type = "application"
	primary.Present = true

	var rel sbom.Relationship
	rel.From = comp1.ID
	rel.To = comp2.ID
	rel.Type = "DEPENDS_ON"

	var relations []sbom.GetRelationship
	relations = append(relations, rel)

	var cmps []sbom.GetComponent
	cmps = append(cmps, comp1, comp2)

	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	doc := sbom.CdxDoc{
		CdxSpec:          spec,
		PrimaryComponent: primary,
		Comps:            cmps,
		Relationships:    relations,
	}

	return doc
}

func cdxCompWithOneDirectDepAndPartOfPrimaryCompDependency() sbom.Document {

	comp1 := sbom.Component{}
	comp1.ID = "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	comp1.Name = "sbomqs-linux-amd64"
	comp1.Version = "v1.0.0"

	comp2 := sbom.Component{}
	comp2.ID = "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"
	comp2.Name = "go-github"
	comp2.Version = "v2.0.0"

	comp3 := sbom.Component{}
	comp3.ID = "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424"
	comp3.Name = "go-crypto"
	comp3.Version = "v3.0.0"

	rel1 := sbom.Relationship{}
	rel1.From = comp1.ID
	rel1.To = comp2.ID
	rel1.Type = "DEPENDS_ON"

	rel2 := sbom.Relationship{}
	rel2.From = comp2.ID
	rel2.To = comp3.ID
	rel2.Type = "DEPENDS_ON"

	primary := sbom.PrimaryComponentInfo{}
	primary.ID = comp1.ID
	primary.Name = comp1.Name
	primary.Version = comp1.Version
	primary.Type = "application"
	primary.Present = true

	var relations []sbom.GetRelationship
	relations = append(relations, rel1, rel2)

	var cmps []sbom.GetComponent
	cmps = append(cmps, comp1, comp2, comp3)

	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"

	doc := sbom.CdxDoc{
		CdxSpec:          spec,
		Relationships:    relations,
		PrimaryComponent: primary,
		Comps:            cmps,
	}
	return doc
}

func cdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency() sbom.Document {
	comp1 := sbom.Component{}
	comp1.ID = "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	comp1.Name = "sbomqs-linux-amd64"
	comp1.Version = "v1.0.0"

	comp2 := sbom.Component{}
	comp2.ID = "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"
	comp2.Name = "go-github"
	comp2.Version = "v2.0.0"

	comp3 := sbom.Component{}
	comp3.ID = "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424"
	comp3.Name = "go-crypto"
	comp3.Version = "v3.0.0"

	comp4 := sbom.Component{}
	comp4.ID = "pkg:golang/github.com/google/go-querystring@v1.1.0"
	comp4.Name = "go-querystring"
	comp4.Version = "v4.0.0"

	rel1 := sbom.Relationship{}
	rel1.From = comp1.ID
	rel1.To = comp2.ID
	rel1.Type = "DEPENDS_ON"

	rel2 := sbom.Relationship{}
	rel2.From = comp2.ID
	rel2.To = comp3.ID
	rel2.Type = "DEPENDS_ON"

	rel3 := sbom.Relationship{}
	rel3.From = comp2.ID
	rel3.To = comp4.ID
	rel3.Type = "DEPENDS_ON"

	primary := sbom.PrimaryComponentInfo{}
	primary.ID = comp1.ID
	primary.Name = comp1.Name
	primary.Version = comp1.Version
	primary.Type = "application"
	primary.Present = true

	var relations []sbom.GetRelationship
	relations = append(relations, rel1, rel2, rel3)

	var cmps []sbom.GetComponent
	cmps = append(cmps, comp1, comp2, comp3, comp4)

	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	doc := sbom.CdxDoc{
		CdxSpec:          spec,
		Relationships:    relations,
		PrimaryComponent: primary,
		Comps:            cmps,
	}

	return doc
}

func spdxCompWithOneDirectDepAndPartOfPrimaryCompDependency() sbom.Document {

	pack1 := sbom.Component{}
	pack1.ID = "SPDXRef-custom-46261-git-github.com-viveksahu26-sbomqs.git-14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	pack1.Name = "sbomqs-linux-amd64"
	pack1.Version = "v0.0.3"

	pack2 := sbom.Component{}
	pack2.ID = "git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"
	pack2.Name = "packageurl-go"
	pack2.Version = "v1.0.1"

	rel1 := sbom.Relationship{}
	rel1.From = pack1.ID
	rel1.To = pack2.ID
	rel1.Type = "DEPENDS_ON"

	primary := sbom.PrimaryComponentInfo{}
	primary.ID = pack1.ID
	primary.Name = pack1.Name
	primary.Version = pack1.Version
	primary.Type = "application"
	primary.Present = true

	var relations []sbom.GetRelationship
	relations = append(relations, rel1)

	var pks []sbom.GetComponent
	pks = append(pks, pack1, pack2)

	spec := sbom.NewSpec()
	spec.SpecType = "spdx"
	doc := sbom.SpdxDoc{
		Relationships:    relations,
		SpdxSpec:         spec,
		PrimaryComponent: primary,
		Comps:            pks,
	}
	return doc
}

func spdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency() sbom.Document {
	pack1 := sbom.Component{}
	pack1.ID = "SPDXRef-custom-46261-git-github.com-viveksahu26-sbomqs.git-14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	pack1.Name = "sbomqs-linux-amd64"
	pack1.Version = "v1.0.0"

	pack2 := sbom.Component{}
	pack2.ID = "git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"
	pack2.Name = "packageurl-go"
	pack2.Version = "v2.0.0"

	pack3 := sbom.Component{}
	pack3.ID = "SPDXRef-git-github.com-samber-lo-151a075ecca084ddbb519fafd513002df0632716"
	pack3.Name = "samber-lo"
	pack3.Version = "v3.0.0"

	pack4 := sbom.Component{}
	pack4.ID = "SPDXRef-git-github.com-github-go-spdx-eacf4f37582f0c1b8f0086816ad1afea74d1ac3f"
	pack4.Name = "go-spdx"
	pack4.Version = "v4.0.0"

	rel1 := sbom.Relationship{}
	rel1.From = pack1.ID
	rel1.To = pack2.ID
	rel1.Type = "DEPENDS_ON"

	rel2 := sbom.Relationship{}
	rel2.From = pack2.ID
	rel2.To = pack3.ID
	rel2.Type = "DEPENDS_ON"

	rel3 := sbom.Relationship{}
	rel3.From = pack2.ID
	rel3.To = pack4.ID
	rel3.Type = "DEPENDS_ON"

	primary := sbom.PrimaryComponentInfo{}
	primary.ID = pack1.ID
	primary.Name = pack1.Name
	primary.Version = pack1.Version
	primary.Type = "application"
	primary.Present = true

	var relations []sbom.GetRelationship
	relations = append(relations, rel1, rel2, rel3)

	var pks []sbom.GetComponent
	pks = append(pks, pack1, pack2, pack3, pack4)

	spec := sbom.NewSpec()
	spec.SpecType = "spdx"
	doc := sbom.SpdxDoc{
		Relationships:    relations,
		SpdxSpec:         spec,
		PrimaryComponent: primary,
		Comps:            pks,
	}

	return doc
}

func TestFsctDependencies(t *testing.T) {
	a := spdxCompWithOneDirectDepAndPartOfPrimaryCompDependency()
	b := spdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency()
	c := cdxCompIsPartOfPrimaryCompDependency()
	d := cdxCompWithOneDirectDepAndPartOfPrimaryCompDependency()
	e := cdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency()

	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxCompWithZeroDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctCompRelationships(a, a.Components()[1]),
			expected: desired{
				score:    0.0,
				result:   "",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(a.Components()[1]),
				maturity: "None",
			},
		},
		{
			name:   "spdxCompWithTwoDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctCompRelationships(b, b.Components()[1]),
			expected: desired{
				score:    10.0,
				result:   "samber-lo, go-spdx",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(b.Components()[1]),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithZeroDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctCompRelationships(c, c.Components()[1]),
			expected: desired{
				score:    0.0,
				result:   "",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(c.Components()[1]),
				maturity: "None",
			},
		},
		{
			name:   "cdxCompWithOneDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctCompRelationships(d, d.Components()[1]),
			expected: desired{
				score:    10.0,
				result:   "go-crypto",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(d.Components()[1]),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithTwoDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctCompRelationships(e, e.Components()[1]),
			expected: desired{
				score:    10.0,
				result:   "go-crypto, go-querystring",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(e.Components()[1]),
				maturity: "Minimum",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

type externalRef struct {
	refCategory string
	refType     string
	refLocator  string
}

func spdxCompWithPurl() sbom.GetComponent {
	urls := []purl.PURL{}
	comp := sbom.NewComponent()

	comp.Name = "go-crypto"
	comp.Spdxid = "SPDXRef-git-github.com-ProtonMail-go-crypto-afb1ddc0824ce0052d72ac0d6917f144a1207424"

	ext := externalRef{
		refCategory: "PACKAGE-MANAGER",
		refType:     "purls",
		refLocator:  "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424",
	}

	prl := purl.NewPURL(ext.refLocator)
	urls = append(urls, prl)
	comp.Purls = urls

	return comp
}

func spdxCompWithCpes() sbom.GetComponent {
	urls := []cpe.CPE{}
	comp := sbom.NewComponent()

	comp.Name = "glibc"
	comp.Spdxid = "SPDXRef-git-github.com-glibc-afb1ddc0824ce0052d72ac0d6917f144a1207424"

	ext := externalRef{
		refCategory: "SECURITY",
		refType:     "cpe23Type",
		refLocator:  "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*",
	}

	prl := cpe.NewCPE(ext.refLocator)
	urls = append(urls, prl)
	comp.Cpes = urls
	return comp
}

func cdxCompWithPurl() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "acme"
	PackageURL := "pkg:npm/acme/component@1.0.0"

	prl := purl.NewPURL(PackageURL)
	comp.Purls = []purl.PURL{prl}

	return comp
}

func cdxCompWithSwhid() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "packageurl-go"
	swh := "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"

	nswhid := swhid.NewSWHID(swh)
	comp.Swhid = append(comp.Swhid, nswhid)

	return comp
}

func cdxCompWithSwid() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "packageurl-go"
	swidTagID := "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1"
	swidName := "Acme Application"

	nswid := swid.NewSWID(swidTagID, swidName)
	comp.Swid = []swid.SWID{nswid}

	return comp
}

func cdxCompWithOmniBorID() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "packageurl-go"
	omniBorID := "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"

	omni := omniborid.NewOmni(omniBorID)
	comp.OmniID = append(comp.OmniID, omni)

	return comp
}

func cdxCompWithPurlOmniSwhidAndSwid() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "acme"

	PackageURL := "pkg:npm/acme/component@1.0.0"
	swh := "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
	swidTagID := "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1"
	swidName := "Acme Application"
	omniBorID := "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"

	prl := purl.NewPURL(PackageURL)
	comp.Purls = []purl.PURL{prl}

	nswhid := swhid.NewSWHID(swh)
	comp.Swhid = append(comp.Swhid, nswhid)

	nswid := swid.NewSWID(swidTagID, swidName)
	comp.Swid = []swid.SWID{nswid}

	omni := omniborid.NewOmni(omniBorID)
	comp.OmniID = append(comp.OmniID, omni)

	return comp
}

func TestFsctUniqIDs(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxWithPurl",
			actual: fsctCompUniqIDs(spdxCompWithPurl()),
			expected: desired{
				score:    10.0,
				result:   "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(spdxCompWithPurl()),
				maturity: "Minimum",
			},
		},
		{
			name:   "spdxWithCpe",
			actual: fsctCompUniqIDs(spdxCompWithCpes()),
			expected: desired{
				score:    10.0,
				result:   "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(spdxCompWithCpes()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxWithPurl",
			actual: fsctCompUniqIDs(cdxCompWithPurl()),
			expected: desired{
				score:    10.0,
				result:   "pkg:npm/acme/component@1.0.0",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithPurl()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithSwhid",
			actual: fsctCompUniqIDs(cdxCompWithSwhid()),
			expected: desired{
				score:    10.0,
				result:   "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithSwhid()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithSwid",
			actual: fsctCompUniqIDs(cdxCompWithSwid()),
			expected: desired{
				score:    10.0,
				result:   "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1, Acme Application",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithSwid()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithOmniborID",
			actual: fsctCompUniqIDs(cdxCompWithOmniBorID()),
			expected: desired{
				score:    10.0,
				result:   "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithOmniBorID()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithPurlOmniSwhidAndSwid",
			actual: fsctCompUniqIDs(cdxCompWithPurlOmniSwhidAndSwid()),
			expected: desired{
				score:    10.0,
				result:   "pkg:npm/acme/component@1.0.0, gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3, swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2, swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1, Acme Application",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithPurlOmniSwhidAndSwid()),
				maturity: "Minimum",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}
