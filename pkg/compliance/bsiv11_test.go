// Copyright 2026 Interlynk.io
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

package compliance

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SBOM Creator fixtures (reused from bsiv11_test.go pattern)

var bsiCdxSBOMAuthor = []byte(`
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

var bsiSpdxSBOMPersonAuthor = []byte(`
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

var bsiSpdxSBOMOrganizationAuthor = []byte(`
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

var bsiCdxSBOMAuthorEmailOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "bom-ref": "author-1",
        "email": "samantha@gmail.com"
      }
    ]
  },
  "components": []
}
`)

var bsiCdxSBOMAuthorNameOnly = []byte(`
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

var bsiCdxSBOMAuthorInvalidEmail = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b00",
  "version": 1,
  "metadata": {
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Samantha Wright",
        "email": "notanemail"
      }
    ]
  },
  "components": []
}
`)

var bsiCdxSBOMAuthorsAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var bsiSpdxSBOMCreationInfoMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {},
  "packages": []
}
`)

// Manufacturer fixtures (CDX uses "manufacture" for metadata-level)
var bsiCdxSBOMManufacturer = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "bom-ref": "manufacture-1",
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ],
      "contact": [
        {
          "bom-ref": "contact-1",
          "name": "Acme Professional Services",
          "email": "professional.services@example.com"
        }
      ]
    }
  },
  "components": []
}
`)

var bsiCdxSBOMManufacturerURLOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "bom-ref": "manufacture-1",
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var bsiCdxSBOMManufacturerContactEmailOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "bom-ref": "manufacture-1",
      "name": "Acme, Inc.",
      "contact": [
        {
          "bom-ref": "contact-1",
          "name": "Acme Professional Services",
          "email": "professional.services@gmail.com"
        }
      ]
    }
  },
  "components": []
}
`)

var bsiCdxSBOMManufacturerNameOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "bom-ref": "manufacture-1",
      "name": "Acme, Inc.",
      "contact": [
        {
          "bom-ref": "contact-1",
          "name": "Acme Professional Services"
        }
      ]
    }
  },
  "components": []
}
`)

// Supplier fixtures
var bsiCdxSBOMSupplier = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ],
      "contact": [
        {
          "name": "Acme Distribution",
          "email": "distribution@example.com"
        }
      ]
    }
  },
  "components": []
}
`)

var bsiCdxSBOMSupplierURLOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var bsiCdxSBOMSupplierContactEmailOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "Acme, Inc.",
      "contact": [
        {
          "name": "Acme Distribution",
          "email": "xyz@gmail.com"
        }
      ]
    }
  },
  "components": []
}
`)

var bsiCdxSBOMSupplierNameOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "Acme, Inc.",
      "contact": [
        {
          "name": "Acme Distribution"
        }
      ]
    }
  },
  "components": []
}
`)

func TestBSISBOMCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMWithAuthorEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "samantha.wright@example.com (author)", got.CheckValue)
	})

	t.Run("spdxSBOMWithPersonAuthorEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "samantha.wright@example.com (author)", got.CheckValue)
	})

	t.Run("spdxSBOMWithOrganizationAuthorEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxSBOMOrganizationAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "samantha.wright@example.com (author)", got.CheckValue)
	})

	t.Run("cdxSBOMWithAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "samantha@gmail.com (author)", got.CheckValue)
	})

	t.Run("cdxSBOMWithAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("cdxSBOMWithInvalidAuthorEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMAuthorInvalidEmail, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("spdxSBOMCreationInfoMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxSBOMCreationInfoMissing, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("cdxSBOMWithManufacturerContactEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMManufacturer, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "https://example.com (manufacturer)", got.CheckValue)
	})

	t.Run("cdxSBOMWithManufacturerURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMManufacturerURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "https://example.com (manufacturer)", got.CheckValue)
	})

	t.Run("cdxSBOMWithManufacturerContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMManufacturerContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "professional.services@gmail.com (manufacturer contact)", got.CheckValue)
	})

	t.Run("cdxSBOMWithManufacturerNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMManufacturerNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})

	t.Run("cdxSBOMWithSupplierContactEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "https://example.com (supplier)", got.CheckValue)
	})

	t.Run("cdxSBOMWithSupplierURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMSupplierURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "https://example.com (supplier)", got.CheckValue)
	})

	t.Run("cdxSBOMWithSupplierContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMSupplierContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "xyz@gmail.com (supplier contact)", got.CheckValue)
	})

	t.Run("cdxSBOMWithSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

//
// SBOM Timestamp fixtures and tests
//

var bsiCdxSBOMWithTimestamp = []byte(`
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

var bsiCdxSBOMNoTimestamp = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var bsiSpdxSBOMWithTimestamp = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": []
}
`)

func TestBSISBOMTimestamp(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMWithValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMWithTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TIMESTAMP, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "2025-01-01T00:00:00Z", got.CheckValue)
	})

	t.Run("spdxSBOMWithValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxSBOMWithTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TIMESTAMP, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "2025-01-01T00:00:00Z", got.CheckValue)
	})

	t.Run("cdxSBOMWithNoTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMNoTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_TIMESTAMP, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

//
// SBOM URI fixtures and tests
//

var bsiSpdxSBOMWithHTTPSNamespace = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/sbom/test-123",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": []
}
`)

var bsiCdxSBOMWithURNSerial = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3337e3a3-62e6-4cbb-abf5-51284a43f9f2",
  "version": 1,
  "components": []
}
`)

var bsiCdxSBOMNoSerial = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": []
}
`)

func TestBSISBOMURI(t *testing.T) {
	ctx := context.Background()

	t.Run("spdxSBOMWithHTTPSNamespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxSBOMWithHTTPSNamespace, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_URI, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Contains(t, got.CheckValue, "https://example.com/sbom/test-123")
	})

	t.Run("cdxSBOMWithURNSerial", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMWithURNSerial, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_URI, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "urn:uuid:3337e3a3-62e6-4cbb-abf5-51284a43f9f2/1", got.CheckValue)
	})

	t.Run("cdxSBOMWithNoSerial", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxSBOMNoSerial, sbom.Signature{})
		require.NoError(t, err)

		got := bsiv11SBOMURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_URI, got.CheckKey)
		assert.Equal(t, "doc", got.ID)
		assert.Equal(t, "", got.CheckValue)
	})
}

//
// Component Creator fixtures and tests
//

var bsiCdxCompAuthor = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "authors": [
        {
          "name": "Anthony Edward Stark",
          "email": "ironman@example.org"
        }
      ]
    }
  ]
}
`)

var bsiSpdxCompPersonSupplier = []byte(`
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
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "supplier": "Person: Samantha Wright (samantha.wright@example.com)"
    }
  ]
}
`)

var bsiSpdxCompOrganizationSupplier = []byte(`
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
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "supplier": "Organization: Samantha Wright (samantha.wright@example.com)"
    }
  ]
}
`)

var bsiCdxCompAuthorNameOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "authors": [
        {
          "name": "Anthony Edward Stark"
        }
      ]
    }
  ]
}
`)

var bsiCdxCompAuthorAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1"
    }
  ]
}
`)

var bsiCdxCompManufacturer = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
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

var bsiCdxCompManufacturerURLOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
        "url": [
          "https://example.com"
        ]
      }
    }
  ]
}
`)

var bsiCdxCompManufacturerContactEmailOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
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

var bsiCdxCompManufacturerNameOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "manufacturer": {
        "name": "Acme, Inc.",
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

var bsiCdxCompSupplier = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
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

var bsiCdxCompSupplierURLOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
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

var bsiCdxCompSupplierContactEmailOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "supplier": {
        "name": "Acme, Inc.",
        "contact": [
          {
            "name": "Acme Professional Services",
            "email": "acme@gmail.com"
          }
        ]
      }
    }
  ]
}
`)

var bsiCdxCompSupplierNameOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "Acme Application",
      "version": "9.1.1",
      "supplier": {
        "name": "Acme, Inc.",
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

func TestBSIComponentCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithAuthorEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompAuthor, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "ironman@example.org (author)", got.CheckValue)
		}
	})

	t.Run("spdxCompWithPersonSupplierEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompPersonSupplier, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "samantha.wright@example.com (supplier)", got.CheckValue)
		}
	})

	t.Run("spdxCompWithOrganizationSupplierEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompOrganizationSupplier, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "samantha.wright@example.com (supplier)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})

	t.Run("cdxCompWithNoCreator", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})

	t.Run("cdxCompWithManufacturerContactEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompManufacturer, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "https://example.com (manufacturer)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithManufacturerURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompManufacturerURLOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "https://example.com (manufacturer)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithManufacturerContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompManufacturerContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "professional.services@example.com (manufacturer contact)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithManufacturerNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompManufacturerNameOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})

	t.Run("cdxCompWithSupplierContactEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompSupplier, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "https://example.com (supplier)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithSupplierURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompSupplierURLOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "https://example.com (supplier)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithSupplierContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompSupplierContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "acme@gmail.com (supplier contact)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentCreator(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_CREATOR, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})
}

//
// Component Name & Version fixtures and tests
//

var bsiCdxCompWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "test-lib@1.0.0",
      "name": "test-lib",
      "version": "1.0.0"
    }
  ]
}
`)

var bsiSpdxCompWithName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "test-lib",
      "versionInfo": "1.0.0"
    }
  ]
}
`)

var bsiCdxCompNoVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "test-lib",
      "name": "test-lib"
    }
  ]
}
`)

func TestBSIComponentName(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentName(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_NAME, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "test-lib", got.CheckValue)
		}
	})

	t.Run("spdxCompWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentName(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_NAME, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "test-lib", got.CheckValue)
		}
	})
}

func TestBSIComponentVersion(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentVersion(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_VERSION, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "1.0.0", got.CheckValue)
		}
	})

	t.Run("spdxCompWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithName, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentVersion(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_VERSION, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "1.0.0", got.CheckValue)
		}
	})

	t.Run("cdxCompMissingVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompNoVersion, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentVersion(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_VERSION, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})
}

//
// Component License fixtures and tests
//

var bsiCdxCompWithValidLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:expr-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "expr-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "Apache-2.0 OR MIT",
          "acknowledgement": "concluded"
        }
      ]
    }
  ]
}
`)

var bsiSpdxCompWithValidLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "expr-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-expr",
      "name": "expr-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "Apache-2.0 OR MIT"
    }
  ]
}
`)

var bsiCdxCompWithCustomLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:custom-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "custom-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "LicenseRef-Acme-Proprietary-License",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

var bsiCdxCompWithInvalidLicenseID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:invalid-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "bad-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "Apache-9999"
          }
        }
      ]
    }
  ]
}
`)

var bsiSpdxCompWithInvalidLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "bad-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-bad",
      "name": "bad-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "Apache-9999"
    }
  ]
}
`)

var bsiCdxCompNoLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "no-license-lib",
      "version": "1.0.0"
    }
  ]
}
`)

var bsiCdxCompWithNoneLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:none-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "none-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "NONE"
        }
      ]
    }
  ]
}
`)

func TestBSIComponentLicense(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithValidLicenseExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithValidLicense, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentLicense(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_LICENSE, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Apache-2.0 (compliant)", got.CheckValue)
		}
	})

	t.Run("spdxCompWithValidLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithValidLicense, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentLicense(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_LICENSE, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Apache-2.0 (compliant)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithCustomLicenseRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithCustomLicense, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentLicense(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_LICENSE, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "LicenseRef-Acme-Proprietary-License (compliant)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithInvalidLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithInvalidLicenseID, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentLicense(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_LICENSE, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Apache-9999 (non-compliant)", got.CheckValue)
		}
	})

	t.Run("spdxCompWithInvalidLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithInvalidLicense, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentLicense(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_LICENSE, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "Apache-9999 (non-compliant)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithNoLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompNoLicense, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentLicense(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_LICENSE, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})

	t.Run("cdxCompWithNoneLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithNoneLicense, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentLicense(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_LICENSE, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})
}

//
// Component Hash fixtures and tests
//

var bsiCdxCompWithSHA256Hash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "hashed-lib",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21"
        }
      ]
    }
  ]
}
`)

var bsiSpdxCompWithSHA256Hash = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "hashed-lib",
      "versionInfo": "1.0.0",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21"
        }
      ]
    }
  ]
}
`)

var bsiCdxCompWithSHA1HashOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "sha1-lib",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        }
      ]
    }
  ]
}
`)

var bsiCdxCompNoHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "nohash-lib",
      "version": "1.0.0"
    }
  ]
}
`)

func TestBSIComponentHash(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentHash(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_HASH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "SHA-256: 64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21", got.CheckValue)
		}
	})

	t.Run("spdxCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentHash(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_HASH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "SHA-256: 64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21", got.CheckValue)
		}
	})

	t.Run("cdxCompWithSHA1HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithSHA1HashOnly, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentHash(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_HASH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})

	t.Run("cdxCompWithNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompNoHash, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentHash(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_HASH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})
}

//
// Component Dependencies fixtures and tests
//

// Leaf component: no outgoing DEPENDS_ON or CONTAINS relations
var bsiCdxCompLeaf = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "leaf-lib",
      "name": "leaf-lib",
      "version": "1.0.0"
    }
  ]
}
`)

// Component with resolvable dependency: both main-lib and dep-lib in components
var bsiCdxCompWithResolvableDep = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "main-lib",
      "name": "main-lib",
      "version": "1.0.0"
    },
    {
      "type": "library",
      "bom-ref": "dep-lib",
      "name": "dep-lib",
      "version": "2.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "main-lib",
      "dependsOn": ["dep-lib"]
    }
  ]
}
`)

// Component with broken dependency: dep target not in components
var bsiCdxCompWithBrokenDep = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "main-lib",
      "name": "main-lib",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "main-lib",
      "dependsOn": ["nonexistent-dep"]
    }
  ]
}
`)

// Component with partial broken deps: one resolves, one doesn't
var bsiCdxCompWithPartialBrokenDep = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "main-lib",
      "name": "main-lib",
      "version": "1.0.0"
    },
    {
      "type": "library",
      "bom-ref": "dep-lib",
      "name": "dep-lib",
      "version": "2.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "main-lib",
      "dependsOn": ["dep-lib", "ghost-lib"]
    }
  ]
}
`)

var bsiSpdxCompLeaf = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-leaf",
      "name": "leaf-lib",
      "versionInfo": "1.0.0"
    }
  ]
}
`)

var bsiSpdxCompWithResolvableDep = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-main",
      "name": "main-lib",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-dep",
      "name": "dep-lib",
      "versionInfo": "2.0.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-main",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-dep"
    }
  ]
}
`)

var bsiSpdxCompWithBrokenDep = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-main",
      "name": "main-lib",
      "versionInfo": "1.0.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-main",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-nonexistent"
    }
  ]
}
`)

func TestBSIComponentDependencies(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxLeafComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompLeaf, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentDependencies(doc, c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_DEPTH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "no-dependencies (leaf element)", got.CheckValue)
		}
	})

	t.Run("spdxLeafComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompLeaf, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentDependencies(doc, c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_DEPTH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "no-dependencies (leaf element)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithResolvableDependency", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithResolvableDep, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			if c.GetName() == "main-lib" {
				got := bsiv11ComponentDependencies(doc, c)

				assert.InDelta(t, 10.0, got.Score, 1e-9)
				assert.Equal(t, COMP_DEPTH, got.CheckKey)
				assert.Equal(t, common.UniqueElementID(c), got.ID)
				assert.Equal(t, "(all dependencies resolved) dep-lib", got.CheckValue)
			}
		}
	})

	t.Run("spdxCompWithResolvableDependency", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithResolvableDep, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			if c.GetName() == "main-lib" {
				got := bsiv11ComponentDependencies(doc, c)

				assert.InDelta(t, 10.0, got.Score, 1e-9)
				assert.Equal(t, COMP_DEPTH, got.CheckKey)
				assert.Equal(t, common.UniqueElementID(c), got.ID)
				assert.Equal(t, "(all dependencies resolved) dep-lib", got.CheckValue)
			}
		}
	})

	t.Run("cdxCompWithBrokenDependency", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithBrokenDep, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentDependencies(doc, c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_DEPTH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "broken-dependencies (nonexistent-dep not found in SBOM)", got.CheckValue)
		}
	})

	t.Run("spdxCompWithBrokenDependency", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithBrokenDep, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentDependencies(doc, c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_DEPTH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "broken-dependencies (nonexistent not found in SBOM)", got.CheckValue)
		}
	})

	t.Run("cdxCompWithPartialBrokenDependency", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithPartialBrokenDep, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			if c.GetName() == "main-lib" {
				got := bsiv11ComponentDependencies(doc, c)

				// Declared 2 deps, only 1 resolves -> broken
				assert.InDelta(t, 0.0, got.Score, 1e-9)
				assert.Equal(t, COMP_DEPTH, got.CheckKey)
				assert.Equal(t, common.UniqueElementID(c), got.ID)
				assert.Equal(t, "broken-dependencies (ghost-lib not found in SBOM)", got.CheckValue)
			}
		}
	})
}

//
// Component Source Code URL fixtures and tests
//

var bsiCdxCompWithSourceCodeURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "vcs-lib",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/vcs-lib"
        }
      ]
    }
  ]
}
`)

var bsiCdxCompNoSourceCodeURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "novcs-lib",
      "version": "1.0.0"
    }
  ]
}
`)

func TestBSIComponentSourceCodeURL(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithSourceCodeURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithSourceCodeURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentSourceCodeURL(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SOURCE_CODE_URL, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "https://github.com/example/vcs-lib", got.CheckValue)
		}
	})

	t.Run("cdxCompNoSourceCodeURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompNoSourceCodeURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentSourceCodeURL(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SOURCE_CODE_URL, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})
}

//
// Component Download URL fixtures and tests
//

var bsiCdxCompWithDownloadURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "dist-lib",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://example.com/download/dist-lib-1.0.0.tar.gz"
        }
      ]
    }
  ]
}
`)

var bsiSpdxCompWithDownloadURL = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "dist-lib",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com/download/dist-lib-1.0.0.tar.gz"
    }
  ]
}
`)

var bsiCdxCompNoDownloadURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "nodist-lib",
      "version": "1.0.0"
    }
  ]
}
`)

func TestBSIComponentDownloadURL(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithDownloadURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithDownloadURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentDownloadURL(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_DOWNLOAD_URL, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "https://example.com/download/dist-lib-1.0.0.tar.gz", got.CheckValue)
		}
	})

	t.Run("spdxCompWithDownloadLocation", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithDownloadURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentDownloadURL(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_DOWNLOAD_URL, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "https://example.com/download/dist-lib-1.0.0.tar.gz", got.CheckValue)
		}
	})

	t.Run("cdxCompNoDownloadURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompNoDownloadURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentDownloadURL(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_DOWNLOAD_URL, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})
}

//
// Component Source Hash fixtures and tests
//

var bsiCdxCompWithSourceHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "hashsrc-lib",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/hashsrc-lib",
          "hashes": [
            {
              "alg": "SHA-256",
              "content": "64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21"
            }
          ]
        }
      ]
    }
  ]
}
`)

var bsiCdxCompNoSourceHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "nohashsrc-lib",
      "version": "1.0.0"
    }
  ]
}
`)

func TestBSIComponentSourceHash(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithSourceHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithSourceHash, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentSourceHash(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SOURCE_HASH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "64440820e5d881ec20bc7b9937fdc9bd67d15ba4637b2e7959a8f31dd12c5b21", got.CheckValue)
		}
	})

	t.Run("cdxCompNoSourceHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompNoSourceHash, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentSourceHash(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_SOURCE_HASH, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})
}

//
// Component Other Unique Identifiers (PURL / CPE) fixtures and tests
//

var bsiCdxCompWithPURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "purl-lib",
      "version": "1.0.0",
      "purl": "pkg:npm/purl-lib@1.0.0"
    }
  ]
}
`)

var bsiCdxCompWithCPE = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "cpe-lib",
      "version": "1.0.0",
      "cpe": "cpe:2.3:a:acme:cpe-lib:1.0.0:*:*:*:*:*:*:*"
    }
  ]
}
`)

var bsiCdxCompWithPURLAndCPE = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "both-lib",
      "version": "1.0.0",
      "purl": "pkg:npm/both-lib@1.0.0",
      "cpe": "cpe:2.3:a:acme:both-lib:1.0.0:*:*:*:*:*:*:*"
    }
  ]
}
`)

var bsiCdxCompNoUniqueID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "noid-lib",
      "version": "1.0.0"
    }
  ]
}
`)

var bsiSpdxCompWithPURL = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "purl-lib",
      "versionInfo": "1.0.0",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceLocator": "pkg:npm/purl-lib@1.0.0",
          "referenceType": "purl"
        }
      ]
    }
  ]
}
`)

func TestBSIComponentOtherUniqueIdentifiers(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithPURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentOtherUniqueIdentifiers(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_OTHER_UNIQ_IDS, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Contains(t, got.CheckValue, "pkg:npm/purl-lib@1.0.0")
		}
	})

	t.Run("cdxCompWithCPEOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithCPE, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentOtherUniqueIdentifiers(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_OTHER_UNIQ_IDS, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Contains(t, got.CheckValue, "cpe:2.3:a:acme:cpe-lib:1.0.0")
		}
	})

	t.Run("cdxCompWithPURLPreferredOverCPE", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompWithPURLAndCPE, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentOtherUniqueIdentifiers(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_OTHER_UNIQ_IDS, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			// PURL takes priority over CPE
			assert.Contains(t, got.CheckValue, "pkg:npm/both-lib@1.0.0")
		}
	})

	t.Run("cdxCompNoUniqueID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiCdxCompNoUniqueID, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentOtherUniqueIdentifiers(c)

			assert.InDelta(t, 0.0, got.Score, 1e-9)
			assert.Equal(t, COMP_OTHER_UNIQ_IDS, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Equal(t, "", got.CheckValue)
		}
	})

	t.Run("spdxCompWithPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiSpdxCompWithPURL, sbom.Signature{})
		require.NoError(t, err)

		for _, c := range doc.Components() {
			got := bsiv11ComponentOtherUniqueIdentifiers(c)

			assert.InDelta(t, 10.0, got.Score, 1e-9)
			assert.Equal(t, COMP_OTHER_UNIQ_IDS, got.CheckKey)
			assert.Equal(t, common.UniqueElementID(c), got.ID)
			assert.Contains(t, got.CheckValue, "pkg:npm/purl-lib@1.0.0")
		}
	})
}
