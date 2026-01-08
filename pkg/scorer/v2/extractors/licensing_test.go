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
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cdxCompValidLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
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

var spdxCompValidLicense = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "Apache-2.0"
    }
  ]
}
`)

var cdxCompValidDeclaredLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
	  "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
			}
        }
      ]
    }
  ]
}
`)

var spdxCompValidDeclaredLicense = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseDeclared": "Apache-2.0"
    }
  ]
}
`)

var cdxCompDeprecatedLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
	  "licenses": [
        {
          "license": {
            "id": "AGPL-1.0",
			"acknowledgement": "concluded"
			}
        }
      ]
    }
  ]
}
`)

var spdxCompDeprecatedLicense = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "AGPL-1.0"
    }
  ]
}
`)

var cdxCompRestrictiveLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
	  "licenses": [
        {
          "license": {
            "id": "GPL-2.0-only",
			"acknowledgement": "concluded"
			}
        }
      ]
    }
  ]
}
`)

var spdxCompRestrictiveLicense = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "GPL-2.0-only"
    }
  ]
}
`)

var cdxCompLicenseAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0"
    }
  ]
}
`)

var spdxCompLicenseAbsent = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0"
    }
  ]
}
`)

var cdxCompLicenseEmptyArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": []
    }
  ]
}
`)

var cdxCompLicenseEmptyObject = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {}
      ]
    }
  ]
}
`)

var cdxCompLicenseIDEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "id": ""
          }
        }
      ]
    }
  ]
}
`)

var spdxCompEmptyString = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": ""
    }
  ]
}
`)

var cdxCompLicenseNameEmpty = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "name": ""
          }
        }
      ]
    }
  ]
}
`)

var cdxCompLicenseInvalidID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "id": "FooBarLicense"
          }
        }
      ]
    }
  ]
}
`)

var cdxCompValidLicenseName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": [
        {
          "license": {
            "name": "Apache License 2.0",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

var cdxCompValidLicenseExpression = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "tomcat-catalina",
      "version": "9.0.14",
      "licenses": [
        {
          "expression": "(Apache-2.0 AND MIT) OR BSD-3-Clause"
		}
      ]
    }
  ]
}
`)

var cdxCompDeclaredExpression = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "name": "acme",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "MIT OR Apache-2.0"
        }
      ]
    }
  ]
}
`)

var spdxCompValidLicenseExpression = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "MIT OR Apache-2.0"
    }
  ]
}
`)

var cdxCompLicenseWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme",
      "version": "0.1.0",
      "licenses": {}
    }
  ]
}
`)

var spdxCompLicenseWrongType = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": {}
    }
  ]
}
`)

var spdxCompWhiteSpaceString = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "  "
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "NOASSERTION"
    }
  ]
}
`)

var spdxCompLicenseNone = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "NOASSERTION"
    }
  ]
}
`)

var spdxCompCustomLicense = []byte(`
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
      "SPDXID": "SPDXRef-Pkg",
      "name": "acme",
      "versionInfo": "0.1.0",
      "licenseConcluded": "LicenseRef-Proprietary"
    }
  ]
}
`)

// CompWithLicenses
func TestCompWithLicenses(t *testing.T) {
	t.Run("cdxCompValidLicenseID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompValidLicense", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompValidLicense, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseAbsent", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseAbsent", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseEmptyArray", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseEmptyObject", func(t *testing.T) {
		ctx := context.Background()
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseEmptyObject, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxCompLicenseIDEmptyString", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseIDEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompEmptyString", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseNameEmpty", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseInvalidID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseInvalidID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompValidLicenseName", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidLicenseName, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompValidLicenseExpression", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompValidLicenseExpression, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseWrongType", func(t *testing.T) {
		ctx := context.Background()
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxCompLicenseWrongType", func(t *testing.T) {
		ctx := context.Background()
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxCompWhiteSpaceString", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWhiteSpaceString, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseNoassertion", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseNoassertion, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseNone", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseNone, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompCustomLicense", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCustomLicense, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// CompWithValidLicenses
func TestCompWithValidLicenses(t *testing.T) {
	t.Run("cdxCompValidLicenseID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithValidLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompValidLicense", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompValidLicense, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithValidLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseInvalidID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseInvalidID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithValidLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompValidLicenseExpression", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompValidLicenseExpression, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithValidLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseNoassertion", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseNoassertion, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithValidLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseNone", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseNone, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithValidLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompCustomLicense", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompCustomLicense, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithValidLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// CompWithDeclaredLicenses
func TestCompWithDeclaredLicenses(t *testing.T) {
	t.Run("cdxCompValidDeclaredLicenseID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidDeclaredLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDeclaredLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompDeclaredExpression", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompDeclaredExpression, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDeclaredLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompValidDeclaredLicense", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompValidDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDeclaredLicenses(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// CompWithDeprecatedLicenses
func TestCompWithDeprecatedLicenses(t *testing.T) {
	t.Run("cdxCompDeprecatedLicenseID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompDeprecatedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDeprecatedLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "fix 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompDeprecatedLicense", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompDeprecatedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDeprecatedLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "fix 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// CompWithRestrictiveLicenses
func TestCompWithRestrictiveLicenses(t *testing.T) {
	t.Run("cdxCompRestrictiveLicenseID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompRestrictiveLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithRestrictiveLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "review 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompRestrictiveLicense", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompRestrictiveLicense, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithRestrictiveLicenses(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "review 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})
}
