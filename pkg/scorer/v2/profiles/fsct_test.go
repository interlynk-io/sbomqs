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

var cdxSBOMAuthorAndTimestamp = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-07T14:10:59Z",
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

var spdxSBOMAuthorAndTimestamp = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

var cdxSBOMAuthorAndTimestampWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-11-02210:59Z",
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

var spdxSBOMAuthorAndTimestampWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2023-01-133:06:03Z",
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

var cdxSBOMAuthorTimestampMissing = []byte(`
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

var spdxSBOMAuthorPersonAndTimestampMissing = []byte(`
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

var spdxSBOMAuthorOrganizationAndTimestampMissing = []byte(`
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
    "created": "2023-01-12T22:06:03Z",
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
    "timestamp": "2025-11-07T14:10:59Z",
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
    "created": "2023-01-12T22:06:03Z",
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
    "timestamp": "2025-11-07T14:10:59Z",
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
    "created": "2023-01-12T22:06:03Z",
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
    "timestamp": "2025-11-07T14:10:59Z",
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
    "created": "2023-01-12T22:06:03Z",
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
    "timestamp": "2025-11-07T14:10:59Z",
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
    "created": "2023-01-12T22:06:03Z",
    "creators": [
      "Tool: cyclonedx-gomod-v1.9.0"
    ]
  },
  "packages": []
}
`)

func TestFSCTSBOMProvenance(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMAuthorAndTimestamp
	t.Run("cdxSBOMAuthorAndTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorAndTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorAndTimestamp
	t.Run("spdxSBOMAuthorAndTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAndTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorTimestampMissing
	t.Run("cdxSBOMAuthorTimestampMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorTimestampMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp missing; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorPersonAndTimestampMissing
	t.Run("spdxSBOMAuthorPersonAndTimestampMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorPersonAndTimestampMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp missing; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorOrganizationAndTimestampMissing
	t.Run("spdxSBOMAuthorOrganizationAndTimestampMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorOrganizationAndTimestampMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp missing; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithEmail
	t.Run("cdxSBOMAuthorWithEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonEmail
	t.Run("spdxSBOMAuthorWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationEmail
	t.Run("spdxSBOMAuthorWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithName
	t.Run("cdxSBOMAuthorWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonName
	t.Run("spdxSBOMAuthorWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationName
	t.Run("spdxSBOMAuthorWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsAbsent
	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorAbsent
	t.Run("spdxSBOMAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorMissing
	t.Run("cdxSBOMAuthorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorPersonMissing
	t.Run("spdxSBOMAuthorPersonMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorPersonMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorOrganizationMissing
	t.Run("spdxSBOMAuthorOrganizationMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorOrganizationMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithEmptyString
	t.Run("cdxSBOMAuthorsWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
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

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithEmptyArrayObject
	t.Run("cdxSBOMAuthorsWithEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorsWithEmptyArray
	t.Run("spdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorAndTimestampWrongType
	t.Run("cdxSBOMAuthorAndTimestampWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorAndTimestampWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance incomplete: creation timestamp present but not RFC3339 compliant; author status evaluated separately", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithNameAndEmailAndTimestampWrongType
	t.Run("spdxSBOMAuthorAndTimestampWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAndTimestampWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance incomplete: creation timestamp present but not RFC3339 compliant; author status evaluated separately", got.Desc)
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

	// cdxSBOMMultipleAuthorsWithNameAndEmail
	t.Run("cdxSBOMMultipleAuthorsWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMultipleAuthorsWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMMultipleAuthorWithNameAndEmail
	t.Run("spdxSBOMMultipleAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMultipleAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMMultipleAuthorsAndTools
	t.Run("cdxSBOMMultipleAuthorsAndTools", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMultipleAuthorsAndTools, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMMultipleAuthorsAndTools
	t.Run("spdxSBOMMultipleAuthorsAndTools", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMultipleAuthorsAndTools, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author identified", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMTool
	t.Run("cdxSBOMTool", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMTool
	t.Run("spdxSBOMTool", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTool, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMProvenance(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM provenance: creation timestamp present; author information missing", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestFSCTSBOMPrimaryComponent(t *testing.T) {
	ctx := context.Background()

	// cdxDepsWithPrimaryCompletenessWithDirectDepsCompleteness
	t.Run("cdxDepsWithPrimaryCompletenessWithDirectDepsCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessWithDirectDepsCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMPrimaryComponent(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM subject defined via primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithPrimaryComponentMissing
	t.Run("cdxWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM primary component not declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithPrimaryComponentWithNameMissing
	t.Run("cdxWithPrimaryComponentWithNameMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPrimaryComponentWithNameMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM primary component declared but lacks name or version", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithPrimaryComponentWithVersionMissing
	t.Run("cdxWithPrimaryComponentWithVersionMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPrimaryComponentWithVersionMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM primary component declared but lacks name or version", got.Desc)
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
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompSupplierWithPersonNameEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierWithWhiteSpaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithWhiteSpaceName, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithOneSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithOneSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxThreeCompWithOneSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxThreeCompWithOneSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithBothSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithBothSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithBothSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithBothSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "supplier attribution missing for 2 components", got.Desc)
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
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompInValidPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompInValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPURLWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPURLWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPURLAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
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
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
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
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSWHIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSWHIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier declared for all components (OmniBOR)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDInValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDInValid, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompOmniborIDWhiteSpace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompOmniborIDWhiteSpace, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompUniqID(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "unique identifier missing for 1 components", got.Desc)
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
		assert.Equal(t, "unique identifier declared for all components (PURL, CPE, SWHID, SWID, OmniBOR)", got.Desc)
		assert.False(t, got.Ignore)
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

var cdxCompChecksumWithOnePresentAndOneMissing = []byte(`
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

var spdxCompChecksumWithOnePresentAndOneMissing = []byte(`
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

func TestFSCTCompChecksum(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (MD5, SHA1, SHA256, SHA512)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (MD5, SHA1, SHA256, SHA512)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompChecksumWeak", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumWeak, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (MD5, SHA1)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompChecksumWeak", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumWeak, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (MD5, SHA1)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompChecksumStrong", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumStrong, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (SHA256, SHA512)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompChecksumStrong", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumStrong, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (SHA256, SHA512)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompChecksumWithEmptyValue", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumWithEmptyValue, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompChecksumWithEmptyValue", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumWithEmptyValue, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompChecksumMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompChecksumMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompChecksumAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompChecksumAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash missing for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompChecksumWithOnePresentAndOneMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompChecksumWithOnePresentAndOneMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (SHA256)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompChecksumWithOnePresentAndOneMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompChecksumWithOnePresentAndOneMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompChecksum(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cryptographic hash declared for all components (SHA256)", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxCompWithConcludedLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
      "name": "STM32CubeH7",
      "version": "1.12.1",
      "licenses": [
        {
          "license": {
            "name": "Apache-2.0",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

var spdxCompWithConcludedLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "Apache-2.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    },
  ]
}
`)

var cdxCompWithPrimaryCompConcludedLicenseIDMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
      "name": "STM32CubeH7",
      "version": "1.12.1"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

var spdxCompWithPrimaryCompConcludedLicenseMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    },
  ]
}
`)

var cdxCompWithPrimaryCompMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z"
  },
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

var spdxCompWithPrimaryCompMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0"
    }
  ]
}
`)

var cdxCompWithDeclaredLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
      "name": "STM32CubeH7",
      "version": "1.12.1",
      "licenses": [
        {
          "license": {
            "name": "Apache-2.0",
            "acknowledgement": "declared"
          }
        }
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "acknowledgement": "declared"
          }
        }
      ]
    }
  ]
}
`)

var spdxCompWithDeclaredLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseDeclared": "Apache-2.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    },
  ]
}
`)

var cdxCompWithPrimaryCompDeclaredLicenseIDMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "component": {
      "type": "application",
      "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
      "name": "STM32CubeH7",
      "version": "1.12.1"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0",
            "acknowledgement": "declared"
          }
        }
      ]
    }
  ]
}
`)

var spdxCompWithPrimaryDeclaredLicenseMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompWithConcludedDeprecatedLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [
          {
            "license": {
              "name": "AGPL-1.0",
              "acknowledgement": "concluded"
            }
          }
        ]
    }
  }
}
`)

var spdxCompWithConcludedDeprecatedLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "AGPL-1.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    },
  ]
}
`)

var cdxCompWithDeclaredDeprecatedLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [
          {
            "license": {
              "name": "AGPL-1.0",
              "acknowledgement": "declared"
            }
          }
        ]
    }
  }
}
`)

var spdxCompWithDeclaredDeprecatedLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseDeclared": "AGPL-1.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompWithConcludedRestrictiveLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [
          {
            "license": {
              "name": "GPL-2.0-only",
              "acknowledgement": "concluded"
            }
          }
        ]
    }
  }
}
`)

var spdxCompWithConcludedRestrictiveLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "GPL-2.0-only"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompWithDeclaredRestrictiveLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [
          {
            "license": {
              "name": "GPL-2.0-only",
              "acknowledgement": "declared"
            }
          }
        ]
    }
  }
}
`)

var spdxCompWithDeclaredRestrictiveLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseDeclared": "GPL-2.0-only"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompLicenseAbsentForNormalComponent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [
          {
            "license": {
              "name": "GPL-2.0-only",
              "acknowledgement": "declared"
            }
          }
        ]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0"
    }
  ]
}
`)

var spdxCompLicenseAbsentForNormalComponent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "GPL-2.0-only"
    },
    {
      "name": "zstd-libs",
      "SPDXID": "SPDXRef-zstd-libs-1.4.5-2.ph3",
      "versionInfo": "1.4.5-2.ph3"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompLicenseNoassertion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [
          {
            "license": {
              "name": "NOASSERTION",
              "acknowledgement": "declared"
            }
          }
        ]
    }
  },
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0"
    }
  ]
}
`)

var spdxCompLicenseNoassertion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-acme",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "NOASSERTION"
    },
    {
      "name": "zstd-libs",
      "SPDXID": "SPDXRef-zstd-libs-1.4.5-2.ph3",
      "versionInfo": "1.4.5-2.ph3"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Pkg-acme",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxPrimaryCompLicenseEmptyArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": []
    }
  }
}
`)

var cdxPrimaryCompLicenseEmptyObject = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [{}]
    }
  }
}
`)

var cdxPrimaryCompLicenseIDEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "licenses": [
          {
            "license": {
            "id": ""
          }
        }
      ]
    }
  }
}
`)

func TestFSCTCompLicense(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithConcludedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryCompConcludedLicenseIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompConcludedLicenseIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met); license present for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryCompConcludedLicenseMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryCompConcludedLicenseMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license coverage cannot be evaluated: primary component missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license coverage cannot be evaluated: primary component missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryCompDeclaredLicenseIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompDeclaredLicenseIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met); license present for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryDeclaredLicenseMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryDeclaredLicenseMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedDeprecatedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedDeprecatedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedDeprecatedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedDeprecatedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredDeprecatedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredDeprecatedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredDeprecatedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredDeprecatedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedRestrictiveLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedRestrictiveLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedRestrictiveLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedRestrictiveLicense, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredRestrictiveLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredRestrictiveLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredRestrictiveLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredRestrictiveLicense, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseAbsentForNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseAbsentForNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared only for primary component (minimum coverage)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseAbsentForNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseAbsentForNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "license declared only for primary component (minimum coverage)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseNoassertion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseNoassertion, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseNoassertion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseNoassertion, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompLicenseEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompLicenseEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompLicenseEmptyObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompLicenseEmptyObject, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompLicenseIDEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompLicenseIDEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompLicense(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "license missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxCompCopyrightForBothPrimaryAndNormalComponent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "copyright": "Copyright 2025, the STM project"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
      "copyright": "Copyright 2025, the Cel project"
    }
  ]
}
`)

var spdxCompCopyrightForBothPrimaryAndNormalComponent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-expr-v0.19.1",
      "name": "cel.dev/expr",
      "versionInfo": "v0.19.1",
      "copyrightText": "Copyright 2025, the Cel project"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-expr-v0.19.1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompCopyrightForPrimaryComponent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "copyright": "Copyright 2025, the STM project"
    }
  }
}
`)

var cdxCompCopyrightMissingForPrimaryComponent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1",
      "copyright": "Copyright 2025, the Cel project"
    }
  ]
}
`)

var spdxCompCopyrightMissingForPrimaryComponent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-expr-v0.19.1",
      "name": "cel.dev/expr",
      "versionInfo": "v0.19.1"
    },
    {
      "SPDXID": "SPDXRef-Package-acme",
      "name": "acme",
      "versionInfo": "v1.9.0",
      "copyrightText": "Copyright 2025, the Acme project"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-expr-v0.19.1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompCopyrightMissingForBoth = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "cel.dev/expr",
      "version": "v0.19.1"
    }
  ]
}
`)

var spdxCompCopyrightMissingForBoth = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-expr-v0.19.1",
      "name": "cel.dev/expr",
      "versionInfo": "v0.19.1"
    },
    {
      "SPDXID": "SPDXRef-Package-acme",
      "name": "acme",
      "versionInfo": "v1.9.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-expr-v0.19.1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompCopyrightWithEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "copyright": ""

    }
  }
}
`)

var spdxCompCopyrightWithEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-expr-v0.19.1",
      "name": "cel.dev/expr",
      "versionInfo": "v0.19.1",
      "copyrightText": ""
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-expr-v0.19.1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompCopyrightAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1"

    }
  }
}
`)

var spdxCompCopyrightAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-expr-v0.19.1",
      "name": "cel.dev/expr",
      "versionInfo": "v0.19.1"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-expr-v0.19.1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxCompCopyrightWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {
        "type": "application",
        "bom-ref": "e42c6c94-705e-45e1-aea0-fd2047f37db3",
        "name": "STM32CubeH7",
        "version": "1.12.1",
        "copyright": {}

    }
  }
}
`)

var spdxCompCopyrightWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-expr-v0.19.1",
      "name": "cel.dev/expr",
      "versionInfo": "v0.19.1",
      "copyrightText": {}
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-expr-v0.19.1",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

func TestFSCTCompCopyright(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompCopyrightForBothPrimaryAndNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompCopyrightForBothPrimaryAndNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "copyright declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompCopyrightForBothPrimaryAndNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCopyrightForBothPrimaryAndNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "copyright declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompCopyrightForPrimaryComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompCopyrightForPrimaryComponent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "copyright declared for all components (full coverage: aspirational)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompCopyrightMissingForPrimaryComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompCopyrightMissingForPrimaryComponent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met); copyright present for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompCopyrightMissingForPrimaryComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCopyrightMissingForPrimaryComponent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met); copyright present for 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompCopyrightMissingForBoth", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompCopyrightMissingForBoth, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompCopyrightMissingForBoth", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCopyrightMissingForBoth, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompCopyrightWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompCopyrightWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompCopyrightWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCopyrightWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompCopyrightAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompCopyrightAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompCopyrightAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCopyrightAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTCompCopyright(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "copyright missing for primary component (minimum expectation not met) and all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompCopyrightWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompCopyrightWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxCompCopyrightWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCopyrightWrongType, sbom.Signature{})
		require.Error(t, err)
	})

}

var cdxDepsWithPrimaryCompletenessWithDirectDepsCompleteness = []byte(`
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

var cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepMissing = []byte(`
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

var cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepIncomplete = []byte(`
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
      "aggregate": "incomplete",
      "dependencies": [
        "pkg:generic/lib-b@3.4.5"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepUnknown = []byte(`
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
      "aggregate": "unknown",
      "dependencies": [
        "pkg:generic/lib-b@3.4.5"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessWithZeroDirectDepsCompleteness = []byte(`
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
        "pkg:generic/my-app@1.0.0"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryMissingCompletenessWithZeroDirectDepsCompleteness = []byte(`
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
  ]
}
`)

var cdxDepsWithPrimaryCompletenessIncompleteWithZeroDirectDepsCompleteness = []byte(`
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
      "aggregate": "incomplete",
      "dependencies": [
        "pkg:generic/my-app@1.0.0"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessIncompleteWithBothDepsIncomplete = []byte(`
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
      "aggregate": "incomplete",
      "dependencies": [
        "pkg:generic/my-app@1.0.0"
      ]
    },
    {
      "aggregate": "incomplete",
      "dependencies": [
        "pkg:generic/lib-a@2.1.0"
      ]
    },
    {
      "aggregate": "incomplete",
      "dependencies": [
        "pkg:generic/lib-b@3.4.5"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessUnknownWithBothDepsMissingCompleteness = []byte(`
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
      "aggregate": "incomplete",
      "dependencies": [
        "pkg:generic/my-app@1.0.0"
      ]
    }
  ]
}
`)

var cdxDepsWithPrimaryCompletenessUnknownWithBothDepsUnknown = []byte(`
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
      "aggregate": "unknown",
      "dependencies": [
        "pkg:generic/my-app@1.0.0"
      ]
    },
    {
      "aggregate": "unknown",
      "dependencies": [
        "pkg:generic/lib-a@2.1.0"
      ]
    },
    {
      "aggregate": "unknown",
      "dependencies": [
        "pkg:generic/lib-b@3.4.5"
      ]
    }
  ]
}
`)

var cdxWithPrimaryComponentMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,

  "metadata": {},
  "components": [],
  "dependencies": [],
  "compositions": []
}
`)

var cdxWithPrimaryComponentWithNameMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,

  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "version": "1.0.0"
    }
  },
  "components": [],
  "dependencies": [],
  "compositions": []
}
`)

var cdxWithPrimaryComponentWithVersionMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "version": 1,

  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app"
    }  
  },
  "components": [],
  "dependencies": [],
  "compositions": []
}
`)

func TestFSCTCompDependencies(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxDepsWithPrimaryCompletenessWithDirectDepsCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessWithDirectDepsCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships and completeness declared for primary component and all direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships declared; completeness missing for 1 of 2 direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepIncomplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepIncomplete, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships and completeness declared for primary component and all direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepUnknown", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessWithOneDepCompleteAndAnotherDepUnknown, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships and completeness declared for primary component and all direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessWithZeroDirectDepsCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessWithZeroDirectDepsCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships declared; completeness missing for 2 of 2 direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryMissingCompletenessWithZeroDirectDepsCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryMissingCompletenessWithZeroDirectDepsCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships declared (2), but dependency completeness missing for primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessIncompleteWithZeroDirectDepsCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessIncompleteWithZeroDirectDepsCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships declared; completeness missing for 2 of 2 direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessIncompleteWithBothDepsIncomplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessIncompleteWithBothDepsIncomplete, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships and completeness declared for primary component and all direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessUnknownWithBothDepsMissingCompleteness", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessUnknownWithBothDepsMissingCompleteness, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships declared; completeness missing for 2 of 2 direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsWithPrimaryCompletenessUnknownWithBothDepsUnknown", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsWithPrimaryCompletenessUnknownWithBothDepsUnknown, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships and completeness declared for primary component and all direct dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := FSCTSBOMRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "dependency relationships cannot be evaluated: primary component missing", got.Desc)
		assert.False(t, got.Ignore)
	})
}
