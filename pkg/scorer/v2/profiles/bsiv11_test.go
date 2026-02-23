package profiles

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cdxSBOMAuthor = []byte(`
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

var spdxSBOMPersonAuthor = []byte(`
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

var cdxSBOMAuthorEmailOnly = []byte(`
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

var spdxSBOMPersonAuthorEmailOnly = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Person: (samantha@example.com)"
    ]
  },
  "packages": []
}
`)

var cdxSBOMAuthorNameOnly = []byte(`
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

var spdxSBOMPersonAuthorNameOnly = []byte(`
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

var spdxSBOMOrganizationAuthor = []byte(`
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

var spdxSBOMOrganizationAuthorEmailOnly = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Organization: (samantha.wright@example.com)"
    ]
  },
  "packages": []
}
`)

var spdxSBOMOrganizationAuthorNameOnly = []byte(`
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

var spdxSBOMCreationInfoMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {},
  "packages": []
}
`)

var cdxSBOMAuthorsEmptyString = []byte(`
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

var spdxSBOMAuthorsEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [""]
  },
  "packages": []
}
`)

var cdxSBOMAuthorsEmptyArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "authors": []
  },
  "components": []
}
`)

var cdxSBOMAuthorsEmptyArrayObject = []byte(`
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

var spdxSBOMAuthorsEmptyArray = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": []
  },
  "packages": []
}
`)

var spdxSBOMCreatorsWrongTypeSomeValue = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["foobar"]
  },
  "packages": []
}
`)

var spdxSBOMCreatorsWhitespace = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["    "]
  },
  "packages": []
}
`)

var cdxSBOMAuthorsWrongType = []byte(`
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

var spdxSBOMAuthorsWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": {}
  },
  "packages": []
}
`)

var cdxSBOMSupplier = []byte(`
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

var cdxSBOMSupplierURLOnly = []byte(`
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

var cdxSBOMSupplierContactEmailOnly = []byte(`
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

var cdxSBOMSupplierNameOnly = []byte(`
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

var cdxSBOMManufacturer = []byte(`
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

var cdxSBOMManufacturerURLOnly = []byte(`
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

var cdxSBOMManufacturerContactEmailOnly = []byte(`
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

var cdxSBOMManufacturerNameOnly = []byte(`
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

var cdxSBOMManufacturerOthersOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "bom-ref": "manufacture-1",
      "address": {
        "bom-ref": "address-1",
        "country": "USA",
        "locality": "San Francisco"
      }
    }
  },
  "components": []
}
`)

var cdxSBOMManufacturerEmpty = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {}
  },
  "components": []
}
`)

var cdxSBOMManufacturerAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMToolOnlyCreator = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": []
}
`)

// CDX: author is present but email is syntactically invalid.
var cdxSBOMAuthorInvalidEmail = []byte(`
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

func TestBSIV11SBOMCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPersonAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPersonAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPersonAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMOrganizationAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMOrganizationAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMOrganizationAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMOrganizationAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMOrganizationAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMOrganizationAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMCreationInfoMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreationInfoMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsEmptyString", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsEmptyString, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMAuthorsEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMCreatorsWrongTypeSomeValue", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWrongTypeSomeValue, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMCreatorsWhitespace", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWhitespace, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMAuthorsWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMAuthorsWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email/URL) provided via supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email/URL) provided via supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email/URL) provided via supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	//
	t.Run("cdxSBOMManufacturer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturer, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email/URL) provided via manufacturer", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMManufacturerURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email/URL) provided via manufacturer", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMManufacturerContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email/URL) provided via manufacturer", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMManufacturerNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufacturerOthersOnly
	t.Run("cdxSBOMManufacturerOthersOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerOthersOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufacturerEmpty
	t.Run("cdxSBOMManufacturerEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufacturerAbsent
	t.Run("cdxSBOMManufacturerAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolOnlyCreator — Tool entries are skipped when building Authors();
	// no manufacturer or supplier either, so the result is "SBOM creator is missing".
	t.Run("spdxSBOMToolOnlyCreator", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolOnlyCreator, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorInvalidEmail: author exists (anyFieldPresent=true) but email
	// fails mail.ParseAddress validation, so score is 0 "present but lacks".
	t.Run("cdxSBOMAuthorInvalidEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorInvalidEmail, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxCompAuthor = []byte(`
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
          "phone": "555-212-970-4133",
          "email": "ironman@example.org"
        },
        {
          "name": "Peter Benjamin Parker",
          "email": "spiderman@example.org"
        }
      ]
    }
  ]
}
`)

var spdxCompPersonSupplier = []byte(`
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
      "supplier": "Person: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var spdxCompOrganizationSupplier = []byte(`
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
      "supplier": "Organization: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var cdxCompAuthorEmailOnly = []byte(`
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

var spdxCompPersonSupplierEmailOnly = []byte(`
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
      "supplier": "Person: (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var spdxCompOrganizationSupplierEmailOnly = []byte(`
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
      "supplier": "Organization:  (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var cdxCompAuthorNameOnly = []byte(`
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

var spdxCompPersonSupplierNameOnly = []byte(`
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
      "supplier": "Person: Samantha Wright",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var spdxCompOrganizationSupplierNameOnly = []byte(`
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
      "supplier": "Organization:  Samantha Wright",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)
var cdxCompAuthorAbsent = []byte(`
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

var spdxCompPersonSupplierAbsent = []byte(`
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
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var cdxCompAuthorEmptyString = []byte(`
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
          "name": "",
          "email": ""
        }
      ]
    }
  ]
}
`)

var spdxCompPersonSupplierEmptyString = []byte(`
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
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "supplier": "Person:  ( )",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)
var cdxCompAuthorEmptyArray = []byte(`
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
      "authors": []
    }
  ]
}
`)

var cdxCompAuthorEmptyArrayObject = []byte(`
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
        {}
      ]
    }
  ]
}
`)

var cdxCompAuthorWrongType = []byte(`
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
      "authors": {}
    }
  ]
}
`)

//

var cdxCompSupplier = []byte(`
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

var cdxCompSupplierURLOnly = []byte(`
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

var cdxCompSupplierContactEmailOnly = []byte(`
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

var cdxCompSupplierNameOnly = []byte(`
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

var cdxCompManufacturer = []byte(`
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

var cdxCompManufacturerURLOnly = []byte(`
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

var cdxCompManufacturerContactEmailOnly = []byte(`
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

var cdxCompManufacturerNameOnly = []byte(`
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

var cdxCompWithMultipleComponents = []byte(`
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
    },
    {
      "type": "application",
      "name": "Zoo Application",
      "version": "9.0.1"
    },
    {
      "type": "library",
      "name": "Bar Application",
      "version": "1.1.1"
    }
  ]
}
`)

var cdxCompInvalidManufacturerWithMultipleComponents = []byte(`
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
    },
    {
      "type": "application",
      "name": "Zoo Application",
      "version": "9.0.1"
    },
    {
      "type": "library",
      "name": "Bar Application",
      "version": "1.1.1"
    }
  ]
}
`)

func TestBSIV11CompCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompOrganizationSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompOrganizationSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompOrganizationSupplierEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompOrganizationSupplierEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompOrganizationSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompOrganizationSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "creator information missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "creator information missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxCompSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	//
	t.Run("cdxCompManufacturer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturer, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithMultipleComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMultipleComponents, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 3.333333333333333, got.Score, 1e-9)
		assert.Equal(t, "1/3 components provide a valid creator contact (email or URL)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompInvalidManufacturerWithMultipleComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompInvalidManufacturerWithMultipleComponents, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/3 components have creator info, but only valid email or URL required", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has "components": [] and no metadata.component, so
	// doc.Components() is empty, exercises the total==0 guard.
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declared in SBOM", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMPersonAuthor has "packages": [], so doc.Components() is empty.
	t.Run("spdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declared in SBOM", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ---------
var cdxWithCompleteDependencies = []byte(`
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

var spdxWithCompleteReplationship = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "my-app",
      "SPDXID": "SPDXRef-my-app",
      "versionInfo": "1.0.0"
    },
    {
      "name": "lib-a",
      "SPDXID": "SPDXRef-lib-a",
      "versionInfo": "2.1.0"
    },
    {
      "name": "lib-b",
      "SPDXID": "SPDXRef-lib-b",
      "versionInfo": "3.4.5"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-a"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-b"
    }
  ]
}
`)

var cdxWithMissingDependenciesSection = []byte(`
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
  "dependencies": []
}
`)

var spdxWithMissingRelationships = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "my-app",
      "SPDXID": "SPDXRef-my-app",
      "versionInfo": "1.0.0"
    },
    {
      "name": "lib-a",
      "SPDXID": "SPDXRef-lib-a",
      "versionInfo": "2.1.0"
    },
    {
      "name": "lib-b",
      "SPDXID": "SPDXRef-lib-b",
      "versionInfo": "3.4.5"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

// libB present in dependency section but missing in components section
var cdxWithMissingSourceDependencyInSBOM = []byte(`
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
    }
  ],

  "dependencies": [
    {
      "ref": "pkg:generic/my-app@1.0.0",
      "dependsOn": [
        "pkg:generic/lib-a@2.1.0"
      ]
    },
    {
      "ref": "pkg:generic/lib-a@2.1.0",
      "dependsOn": []
    },
    {
      "ref": "pkg:generic/lib-b@3.4.5",
      "dependsOn": [
        "pkg:generic/lib-a@2.1.0"
      ]
    }
  ]
}
`)

var spdxWithMissingSourceRelationshipInSBOM = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "my-app",
      "SPDXID": "SPDXRef-my-app",
      "versionInfo": "1.0.0"
    },
    {
      "name": "lib-a",
      "SPDXID": "SPDXRef-lib-a",
      "versionInfo": "2.1.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    },
    {
      "spdxElementId": "SPDXRef-lib-b",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-a"
    }
  ]
}
`)

// libA present in dependency section as part of direct deps of primary component but missing in components section
var cdxWithMissingTargetDependencyInSBOM = []byte(`
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

var spdxWithMissingTargetRelationshipInSBOM = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "my-app",
      "SPDXID": "SPDXRef-my-app",
      "versionInfo": "1.0.0"
    },
    {
      "name": "lib-b",
      "SPDXID": "SPDXRef-lib-b",
      "versionInfo": "3.4.5"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-a"
    }
  ]
}
`)

// component "lib-c" is present in the SBOM, but it is not reference in the dependency section.
var cdxWithOrphanComponentInSBOM = []byte(`
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
      "bom-ref": "pkg:generic/lib-c@6.0.5",
      "type": "library",
      "name": "lib-c",
      "version": "6.0.5"
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

var spdxWithOrphanComponentInSBOM = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "my-app",
      "SPDXID": "SPDXRef-my-app",
      "versionInfo": "1.0.0"
    },
    {
      "name": "lib-a",
      "SPDXID": "SPDXRef-lib-a",
      "versionInfo": "2.1.0"
    },
    {
      "name": "lib-b",
      "SPDXID": "SPDXRef-lib-b",
      "versionInfo": "3.4.5"
    },
    {
      "name": "lib-c",
      "SPDXID": "SPDXRef-lib-c",
      "versionInfo": "6.0.5"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-a"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-b"
    }
  ]
}
`)

var cdxWithPrimaryCompDepenencyMissingButOthersPresent = []byte(`
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
      "dependsOn": []
    },
    {
      "ref": "pkg:generic/lib-a@2.1.0",
      "dependsOn": []
    },
    {
      "ref": "pkg:generic/lib-b@3.4.5",
      "dependsOn": [
	  	"pkg:generic/lib-a@2.1.0"
	  ]
    }
  ]
}
`)

var spdxWithPrimaryCompRelationshipMissingButOthersPresent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "my-app",
      "SPDXID": "SPDXRef-my-app",
      "versionInfo": "1.0.0"
    },
    {
      "name": "lib-a",
      "SPDXID": "SPDXRef-lib-a",
      "versionInfo": "2.1.0"
    },
    {
      "name": "lib-b",
      "SPDXID": "SPDXRef-lib-b",
      "versionInfo": "3.4.5"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    },
    {
      "spdxElementId": "SPDXRef-lib-b",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-a"
    }
  ]
}
`)

var cdxWithMissingDependencies = []byte(`
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
      "dependsOn": []
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

var spdxWithMissingRelationship = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:11111111-2222-3333-4444-555555555555",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "my-app",
      "SPDXID": "SPDXRef-my-app",
      "versionInfo": "1.0.0"
    },
    {
      "name": "lib-a",
      "SPDXID": "SPDXRef-lib-a",
      "versionInfo": "2.1.0"
    },
    {
      "name": "lib-b",
      "SPDXID": "SPDXRef-lib-b",
      "versionInfo": "3.4.5"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

// CDX: deep transitive chain, primary -> lib-b -> lib-c -> lib-d.
// DFS must recurse all the way through; all components end up visited -> score 10.
var cdxWithDeepTransitiveDependencies = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:deep-cdx-0001",
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
      "bom-ref": "pkg:generic/lib-b@2.0.0",
      "type": "library",
      "name": "lib-b",
      "version": "2.0.0"
    },
    {
      "bom-ref": "pkg:generic/lib-c@3.0.0",
      "type": "library",
      "name": "lib-c",
      "version": "3.0.0"
    },
    {
      "bom-ref": "pkg:generic/lib-d@4.0.0",
      "type": "library",
      "name": "lib-d",
      "version": "4.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:generic/my-app@1.0.0",
      "dependsOn": ["pkg:generic/lib-b@2.0.0"]
    },
    {
      "ref": "pkg:generic/lib-b@2.0.0",
      "dependsOn": ["pkg:generic/lib-c@3.0.0"]
    },
    {
      "ref": "pkg:generic/lib-c@3.0.0",
      "dependsOn": ["pkg:generic/lib-d@4.0.0"]
    },
    {
      "ref": "pkg:generic/lib-d@4.0.0",
      "dependsOn": []
    }
  ]
}
`)

// SPDX: deep transitive chain: my-app -> lib-b -> lib-c -> lib-d.
var spdxWithDeepTransitiveDependencies = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "deep-chain-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:deep-spdx-0001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    { "SPDXID": "SPDXRef-my-app", "name": "my-app", "versionInfo": "1.0.0" },
    { "SPDXID": "SPDXRef-lib-b",  "name": "lib-b",  "versionInfo": "2.0.0" },
    { "SPDXID": "SPDXRef-lib-c",  "name": "lib-c",  "versionInfo": "3.0.0" },
    { "SPDXID": "SPDXRef-lib-d",  "name": "lib-d",  "versionInfo": "4.0.0" }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-b"
    },
    {
      "spdxElementId": "SPDXRef-lib-b",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-c"
    },
    {
      "spdxElementId": "SPDXRef-lib-c",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-d"
    }
  ]
}
`)

// CDX: cyclic dependency: primary -> lib-b -> primary.
var cdxWithCyclicDependencies = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:cyclic-cdx-0001",
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
      "bom-ref": "pkg:generic/lib-b@2.0.0",
      "type": "library",
      "name": "lib-b",
      "version": "2.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:generic/my-app@1.0.0",
      "dependsOn": ["pkg:generic/lib-b@2.0.0"]
    },
    {
      "ref": "pkg:generic/lib-b@2.0.0",
      "dependsOn": ["pkg:generic/my-app@1.0.0"]
    }
  ]
}
`)

// SPDX: cyclic dependency: my-app -> lib-b -> my-app.
var spdxWithCyclicDependencies = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "cyclic-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:cyclic-spdx-0001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    { "SPDXID": "SPDXRef-my-app", "name": "my-app", "versionInfo": "1.0.0" },
    { "SPDXID": "SPDXRef-lib-b",  "name": "lib-b",  "versionInfo": "2.0.0" }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-lib-b"
    },
    {
      "spdxElementId": "SPDXRef-lib-b",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

func TestBSIV11CompDependencies(t *testing.T) {
	ctx := context.Background()

	// cdxWithCompleteDependencies
	t.Run("cdxWithCompleteDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithCompleteDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithCompleteReplationship
	t.Run("spdxWithCompleteReplationship", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithCompleteReplationship, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingDependenciesSection
	t.Run("cdxWithMissingDependenciesSection", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingDependenciesSection, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingRelationships
	t.Run("spdxWithMissingRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingSourceDependencyInSBOM
	t.Run("cdxWithMissingSourceDependencyInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingSourceDependencyInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency source references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingSourceRelationshipInSBOM
	t.Run("spdxWithMissingSourceRelationshipInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingSourceRelationshipInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency source references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingTargetDependencyInSBOM
	t.Run("cdxWithMissingTargetDependencyInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingTargetDependencyInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency target references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingTargetRelationshipInSBOM
	t.Run("spdxWithMissingTargetRelationshipInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingTargetRelationshipInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency target references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithOrphanComponentInSBOM
	t.Run("cdxWithOrphanComponentInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithOrphanComponentInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "Some components are not reachable from the primary component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithOrphanComponentInSBOM
	t.Run("spdxWithOrphanComponentInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithOrphanComponentInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "Some components are not reachable from the primary component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithPrimaryCompDepenencyMissingButOthersPresent
	t.Run("cdxWithPrimaryCompDepenencyMissingButOthersPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPrimaryCompDepenencyMissingButOthersPresent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component does not declare its dependencies.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithPrimaryCompRelationshipMissingButOthersPresent
	t.Run("spdxWithPrimaryCompRelationshipMissingButOthersPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithPrimaryCompRelationshipMissingButOthersPresent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component does not declare its dependencies.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingDependencies
	t.Run("cdxWithMissingDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingRelationship
	t.Run("spdxWithMissingRelationship", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingRelationship, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompWithPrimaryCompMissing
	t.Run("cdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompWithPrimaryCompMissing
	t.Run("spdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithDeepTransitiveDependencies: DFS must recurse through 4 levels;
	// all nodes reachable -> score 10.
	t.Run("cdxWithDeepTransitiveDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithDeepTransitiveDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithDeepTransitiveDependencies
	t.Run("spdxWithDeepTransitiveDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithDeepTransitiveDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithCyclicDependencies: visited-guard prevents infinite recursion
	t.Run("cdxWithCyclicDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithCyclicDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithCyclicDependencies
	t.Run("spdxWithCyclicDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithCyclicDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxCompWithLicenseExpression = []byte(`
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

var spdxCompWithLicenseExpression = []byte(`
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

var cdxCompWithCustomLicense = []byte(`
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

var spdxCompWithCustomLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "custom-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-custom",
      "name": "custom-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "LicenseRef-Acme-Proprietary"
    }
  ]
}
`)

var cdxCompWithNoneLicense = []byte(`
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

var spdxCompWithNoneLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "none-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-none",
      "name": "none-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "NONE"
    }
  ]
}
`)

var cdxCompWithNoAssertionLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:noassert-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "na-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "NOASSERTION"
        }
      ]
    }
  ]
}
`)

var spdxCompWithNoAssertionLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "na-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-na",
      "name": "na-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "NOASSERTION"
    }
  ]
}
`)

var cdxCompWithInvalidLicenseID = []byte(`
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

var spdxCompWithInvalidLicenseID = []byte(`
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

var cdxCompWithInvalidExpression = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:badexpr-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "bad-expr-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "Apache-2.0 OR"
        }
      ]
    }
  ]
}
`)

var spdxCompWithInvalidExpression = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "badexpr-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-badexpr",
      "name": "bad-expr-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "Apache-2.0 OR"
    }
  ]
}
`)

var cdxCompWithMixedLicenses = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:mixed-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "mixed-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "license": { "id": "MIT" }
        },
        {
          "license": { "id": "FakeLicense-1.0" }
        }
      ]
    }
  ]
}
`)

var spdxCompWithMixedLicenses = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "mixed-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-mixed",
      "name": "mixed-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "MIT AND FakeLicense-1.0"
    }
  ]
}
`)

var cdxCompWithInvalidLicenseSPDXID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:badexpr-1111",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "bad-expr-lib",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "Apache License"
        }
      ]
    }
  ]
}
`)

var spdxCompWithInvalidLicenseSPDXID = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "badexpr-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: sbomqs"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg-badexpr",
      "name": "bad-expr-lib",
      "versionInfo": "1.0.0",
      "licenseConcluded": "Apache License"
    }
  ]
}
`)

func TestBSIV11CompLicense(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithLicenseExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithLicenseExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithLicenseExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithLicenseExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithCustomLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithCustomLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithCustomLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithCustomLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoneLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoneLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithNoneLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoneLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoAssertionLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoAssertionLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithNoAssertionLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoAssertionLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithInvalidLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have invalid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithInvalidLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithInvalidLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have invalid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithInvalidExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have invalid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithInvalidExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithInvalidExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have invalid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithMixedLicenses", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMixedLicenses, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithMixedLicenses", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMixedLicenses, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have invalid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithInvalidLicenseSPDXID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidLicenseSPDXID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have invalid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithInvalidLicenseSPDXID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithInvalidLicenseSPDXID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1/1 components have invalid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryCompConcludedLicenseIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompConcludedLicenseIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components have valid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryCompConcludedLicenseMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryCompConcludedLicenseMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedDeprecatedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedDeprecatedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedDeprecatedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedDeprecatedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredDeprecatedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredDeprecatedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredDeprecatedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredDeprecatedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedRestrictiveLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedRestrictiveLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedRestrictiveLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedRestrictiveLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredRestrictiveLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredRestrictiveLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredRestrictiveLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredRestrictiveLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseAbsentForNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseAbsentForNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components have valid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseAbsentForNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseAbsentForNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components have valid licence info", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompLicenseEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompLicenseEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompLicenseEmptyObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompLicenseEmptyObject, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has "components": [] and no metadata.component → exercises total==0 guard.
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found in SBOM.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMPersonAuthor has "packages": [] → doc.Components() is empty.
	t.Run("spdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found in SBOM.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// BSIV11CompExecutableHash test cases

// CDX: primary component with a valid SHA-256 hash
var cdxPrimaryCompWithSHA256Hash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:hash-cdx-0001",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "aec070645fe53ee3b3763059376134f058cc337247c978616ddbb"
        }
      ]
    }
  },
  "components": []
}
`)

// CDX: primary component with MD5 hash only (not SHA-256)
var cdxPrimaryCompWithMD5HashOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:hash-cdx-0002",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "MD5",
          "content": "d41d8cd98f00b204e9800998ecf8427e"
        }
      ]
    }
  },
  "components": []
}
`)

// CDX: primary component with SHA-1 hash only (not SHA-256)
var cdxPrimaryCompWithSHA1HashOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:hash-cdx-0003",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        }
      ]
    }
  },
  "components": []
}
`)

// CDX: primary component with SHA-512 hash only (not SHA-256)
var cdxPrimaryCompWithSHA512HashOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:hash-cdx-0004",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-512",
          "content": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    }
  },
  "components": []
}
`)

// CDX: primary component with SHA-256 present but empty hash value
var cdxPrimaryCompWithSHA256EmptyValue = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:hash-cdx-0005",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": ""
        }
      ]
    }
  },
  "components": []
}
`)

// CDX: primary component with no hashes at all
var cdxPrimaryCompWithNoHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:hash-cdx-0006",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "components": []
}
`)

// CDX: primary component with multiple hashes including SHA-256
var cdxPrimaryCompWithMultipleHashesIncludingSHA256 = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:hash-cdx-0007",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "pkg:generic/my-app@1.0.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "MD5",
          "content": "d41d8cd98f00b204e9800998ecf8427e"
        },
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        {
          "alg": "SHA-256",
          "content": "aec070645fe53ee3b3763059376134f058cc337247c978616ddbb"
        }
      ]
    }
  },
  "components": []
}
`)

// SPDX: primary component with a valid SHA256 checksum
var spdxPrimaryCompWithSHA256Hash = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:hash-spdx-0001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "aec070645fe53ee3b3763059376134f058cc337247c978616ddbb"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

// SPDX: primary component with SHA1 hash only (not SHA256)
var spdxPrimaryCompWithSHA1HashOnly = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:hash-spdx-0002",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

// SPDX: primary component with MD5 hash only (not SHA256)
var spdxPrimaryCompWithMD5HashOnly = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:hash-spdx-0003",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "checksums": [
        {
          "algorithm": "MD5",
          "checksumValue": "d41d8cd98f00b204e9800998ecf8427e"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

// SPDX: primary component with no checksums at all
var spdxPrimaryCompWithNoHash = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:hash-spdx-0004",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

// SPDX: primary component with multiple checksums including SHA256
var spdxPrimaryCompWithMultipleHashesIncludingSHA256 = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:hash-spdx-0005",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "checksums": [
        {
          "algorithm": "MD5",
          "checksumValue": "d41d8cd98f00b204e9800998ecf8427e"
        },
        {
          "algorithm": "SHA1",
          "checksumValue": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        {
          "algorithm": "SHA256",
          "checksumValue": "aec070645fe53ee3b3763059376134f058cc337247c978616ddbb"
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

// SPDX: primary component with SHA256 present but checksumValue is empty string.
var spdxPrimaryCompWithSHA256EmptyValue = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:hash-spdx-0006",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "   "
        }
      ]
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-my-app"
    }
  ]
}
`)

func TestBSIV11CompExecutableHash(t *testing.T) {
	ctx := context.Background()

	// cdxPrimaryCompWithSHA256Hash
	t.Run("cdxPrimaryCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable declares a valid SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxPrimaryCompWithSHA256Hash
	t.Run("spdxPrimaryCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable declares a valid SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxPrimaryCompWithMD5HashOnly
	t.Run("cdxPrimaryCompWithMD5HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithMD5HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxPrimaryCompWithMD5HashOnly
	t.Run("spdxPrimaryCompWithMD5HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithMD5HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxPrimaryCompWithSHA1HashOnly
	t.Run("cdxPrimaryCompWithSHA1HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA1HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxPrimaryCompWithSHA1HashOnly
	t.Run("spdxPrimaryCompWithSHA1HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithSHA1HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxPrimaryCompWithSHA512HashOnly
	t.Run("cdxPrimaryCompWithSHA512HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA512HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxPrimaryCompWithSHA256EmptyValue
	t.Run("cdxPrimaryCompWithSHA256EmptyValue", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA256EmptyValue, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxPrimaryCompWithNoHash
	t.Run("cdxPrimaryCompWithNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxPrimaryCompWithNoHash
	t.Run("spdxPrimaryCompWithNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxPrimaryCompWithMultipleHashesIncludingSHA256
	t.Run("cdxPrimaryCompWithMultipleHashesIncludingSHA256", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithMultipleHashesIncludingSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable declares a valid SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxPrimaryCompWithMultipleHashesIncludingSHA256
	t.Run("spdxPrimaryCompWithMultipleHashesIncludingSHA256", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithMultipleHashesIncludingSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable declares a valid SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompWithPrimaryCompMissing (reused from fsct_test.go — no DESCRIBES relationship)
	t.Run("spdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxPrimaryCompWithSHA256EmptyValue
	t.Run("spdxPrimaryCompWithSHA256EmptyValue", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithSHA256EmptyValue, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary executable component must declare a SHA-256 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===================================
// TestBSIV11SBOMCreationTimestamp
// ===================================

// cdxSBOMWithValidTimestamp — metadata.timestamp is a valid RFC3339 timestamp.
var cdxSBOMWithValidTimestamp = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-01T00:00:00Z"
  },
  "components": []
}
`)

// spdxSBOMWithValidTimestamp — creationInfo.created is a valid RFC3339 timestamp.
var spdxSBOMWithValidTimestamp = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": []
}
`)

var cdxSBOMWithInvalidTimestamp = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "01-01-2026"
  },
  "components": []
}
`)

var spdxSBOMWithInvalidTimestamp = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "01-01-2026",
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": []
}
`)

func TestBSIV11SBOMCreationTimestamp(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithValidTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreationTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is valid and RFC3339-compliant.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithValidTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreationTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is valid and RFC3339-compliant.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has no metadata.timestamp -> GetCreationTimestamp() returns "" -> missing.
	t.Run("cdxWithMissingTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMPersonAuthor has no creationInfo.created -> GetCreationTimestamp() returns "" -> missing.
	t.Run("spdxWithMissingTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	// "01-01-2026" is present but not RFC3339
	t.Run("cdxWithInvalidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithInvalidTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is not a valid RFC3339 (ISO-8601) timestamp.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithInvalidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithInvalidTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is not a valid RFC3339 (ISO-8601) timestamp.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ====================
// TestBSIV11CompName
// ====================

func TestBSIV11CompName(t *testing.T) {
	ctx := context.Background()

	// cdxCompAuthorAbsent has one component: {"name": "Acme Application", "version": "9.1.1"}.
	t.Run("cdxSingleNamedComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompName(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "component name declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompPersonSupplierAbsent has one package with name "application-a".
	t.Run("spdxSingleNamedPackage", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompName(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "component name declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has "components": [] -> total == 0.
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompName(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declared in SBOM", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMPersonAuthor has "packages": [] -> total == 0.
	t.Run("spdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompName(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declared in SBOM", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// =======================
// TestBSIV11CompVersion
// =======================

// cdxCompWithMissingVersion
var cdxCompWithMissingVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo"
    }
  ]
}
`)

// spdxCompWithMissingVersion
var spdxCompWithMissingVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "libfoo"
    }
  ]
}
`)

// spdxWithPartialVersions: two SPDX packages: first has versionInfo, second does not.
var spdxWithPartialVersions = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-PkgA",
      "name": "libfoo",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-PkgB",
      "name": "libbar"
    }
  ]
}
`)

func TestBSIV11CompVersion(t *testing.T) {
	ctx := context.Background()

	// cdxCompAuthorAbsent has one component with version "9.1.1".
	t.Run("cdxAllComponentsHaveVersions", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompVersion(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "component version declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompPersonSupplierAbsent has one package with versionInfo "1.0".
	t.Run("spdxAllPackagesHaveVersions", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompVersion(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "component version declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has "components": [] -> total == 0.
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompVersion(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declared in SBOM", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMPersonAuthor has "packages": [] -> total == 0.
	t.Run("spdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompVersion(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declared in SBOM", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX component without version field -> GetVersion() returns "" -> 1 missing out of 1.
	t.Run("cdxWithMissingVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMissingVersion, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompVersion(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component version missing for 1 out of 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX package without versionInfo
	t.Run("spdxWithMissingVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMissingVersion, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompVersion(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component version missing for 1 out of 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// Two SPDX packages: one with version, one without -> 1 missing out of 2.
	t.Run("spdxWithPartialVersions", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithPartialVersions, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompVersion(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component version missing for 1 out of 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV11SBOMURI
// ===========================================================================

// cdxSBOMWithoutSerialNumber — CDX BOM with no serialNumber field.
// sp.URI is only set when serialNumber is non-empty and starts with "urn:uuid:",
// so GetURI() returns "" → "SBOM-URI is missing", Ignore: true.
var cdxSBOMWithoutSerialNumber = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-01-01T00:00:00Z"
  },
  "components": []
}
`)

// spdxSBOMWithDocumentNamespace — SPDX with a valid HTTP documentNamespace.
// sp.URI = documentNamespace → isValidURL passes → score 10.
var spdxSBOMWithDocumentNamespace = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.com/sboms/my-sbom-v1.0",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": []
}
`)

// spdxSBOMWithInvalidNamespace — SPDX documentNamespace is neither a URL nor a URN.
// isValidURL("not-a-valid-uri") = false and no "urn:" prefix → score 0, Ignore: false.
var spdxSBOMWithInvalidNamespace = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "not-a-valid-uri",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": []
}
`)

func TestBSIV11SBOMURI(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMAuthor has "serialNumber": "urn:uuid:..." and "version": 1
	// → sp.URI = "urn:uuid:.../1" which starts with "urn:" → score 10.
	t.Run("cdxWithValidSerialNumber", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is declared.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithDocumentNamespaceURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithDocumentNamespace, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is declared.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// No serialNumber → sp.URI = "" → missing, optional field → Ignore: true.
	t.Run("cdxWithoutSerialNumber", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithoutSerialNumber, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is missing (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// spdxSBOMPersonAuthor has no documentNamespace → sp.URI = "" → Ignore: true.
	t.Run("spdxWithoutDocumentNamespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is missing (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// documentNamespace is present but not a URL and not a URN → invalid, Ignore: false.
	t.Run("spdxWithInvalidNamespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithInvalidNamespace, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is present but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV11CompSourceURI
// ===========================================================================

var cdxCompWithVCSRef = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://github.com/example/libfoo",
          "type": "vcs"
        }
      ]
    }
  ]
}
`)

var cdxCompWithSourceDistributionRef = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://example.com/libfoo-1.0.0-source.tar.gz",
          "type": "source-distribution"
        }
      ]
    }
  ]
}
`)

var cdxTwoCompsOneWithSourceURI = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://github.com/example/libfoo",
          "type": "vcs"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-2",
      "name": "libbar",
      "version": "2.0.0"
    }
  ]
}
`)

var cdxCompWithInvalidSourceURI = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "not-a-valid-url",
          "type": "vcs"
        }
      ]
    }
  ]
}
`)

func TestBSIV11CompSourceURI(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithVCSRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Source code URI declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxWithSourceDistributionRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithSourceDistributionRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Source code URI declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLAbsent has one component with no externalReferences -> SourceCodeURL = "".
	t.Run("cdxNoSourceRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare source code URI (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// VCS externalRef is present but its URL is not a valid URL
	t.Run("cdxWithInvalidSourceURI", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidSourceURI, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Source code URI declared but invalid for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX has no deterministic source-code-URI field.
	t.Run("spdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLValid, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare source code URI (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// 1 out of 2 components has a source URI
	t.Run("cdxPartialSourceURI", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompsOneWithSourceURI, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceURI(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare source code URI.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has no components
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV11CompExecutableURI
// ===========================================================================

var cdxCompWithDistributionRef = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://registry.example.com/libfoo-1.0.0.tar.gz",
          "type": "distribution"
        }
      ]
    }
  ]
}
`)

var cdxCompWithDistributionIntakeRef = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://intake.example.com/libfoo-1.0.0.tar.gz",
          "type": "distribution-intake"
        }
      ]
    }
  ]
}
`)

var spdxCompWithValidDownloadLocation = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "libfoo",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com/libfoo-1.0.0.tar.gz"
    }
  ]
}
`)

var spdxCompWithNoassertionLocation = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "libfoo",
      "versionInfo": "1.0.0",
      "downloadLocation": "NOASSERTION"
    }
  ]
}
`)

var cdxTwoCompsOneWithDistributionRef = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://registry.example.com/libfoo-1.0.0.tar.gz",
          "type": "distribution"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-2",
      "name": "libbar",
      "version": "2.0.0"
    }
  ]
}
`)

var cdxCompWithInvalidExecutableURI = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "not-a-valid-url",
          "type": "distribution"
        }
      ]
    }
  ]
}
`)

func TestBSIV11CompExecutableURI(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithDistributionRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDistributionRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Executable URI declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxWithDistributionIntakeRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDistributionIntakeRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Executable URI declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithValidDownloadLocation", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithValidDownloadLocation, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Executable URI declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX PackageDownloadLocation = "NOASSERTION"
	t.Run("spdxWithNoassertionLocation", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoassertionLocation, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Executable URI declared but invalid for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLAbsent has one component with no externalReferences
	t.Run("cdxNoDownloadRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare executable URI (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// Distribution externalRef is present but its URL is not a valid URL
	t.Run("cdxWithInvalidExecutableURI", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidExecutableURI, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Executable URI declared but invalid for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 1 out of 2 components has a distribution ref
	t.Run("cdxPartialExecutableURI", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompsOneWithDistributionRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare executable URI.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has no components
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompExecutableURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV11CompSourceHash
// ===========================================================================

var cdxCompWithVCSAndSHA256 = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://github.com/example/libfoo",
          "type": "vcs",
          "hashes": [
            {
              "alg": "SHA-256",
              "content": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            }
          ]
        }
      ]
    }
  ]
}
`)

var cdxCompWithSourceDistributionAndSHA256 = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://example.com/libfoo-1.0.0-source.tar.gz",
          "type": "source-distribution",
          "hashes": [
            {
              "alg": "SHA-256",
              "content": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            }
          ]
        }
      ]
    }
  ]
}
`)

var cdxCompWithVCSAndNonSHA256Hash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "externalReferences": [
        {
          "url": "https://github.com/example/libfoo",
          "type": "vcs",
          "hashes": [
            {
              "alg": "MD5",
              "content": "c3d43dcbd0fe759f08bf015a813a9b8a"
            }
          ]
        }
      ]
    }
  ]
}
`)

var spdxCompWithVerificationCode = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "libfoo",
      "versionInfo": "1.0.0",
      "packageVerificationCode": {
        "packageVerificationCodeValue": "d6a770ba38583ed4bb4525bd96e50461655d2758"
      }
    }
  ]
}
`)

func TestBSIV11CompSourceHash(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxVCSSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSAndSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSourceDistributionSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithSourceDistributionAndSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithVerificationCode", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithVerificationCode, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// VCS ref present but only MD5 hash
	t.Run("cdxVCSNonSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSAndNonSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare source hash (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// cdxCompWithVCSRef has a VCS ref but no hashes array
	t.Run("cdxVCSRefWithNoHashes", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare source hash (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// cdxCompPURLAbsent has one component with no externalReferences
	t.Run("cdxNoSourceRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare source hash (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// cdxSBOMAuthor has no components
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV11CompOtherIdentifiers
// ===========================================================================

var cdxCompWithCPEOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "cpe": "cpe:2.3:a:example:libfoo:1.0.0:*:*:*:*:*:*:*"
    }
  ]
}
`)

var spdxCompWithCPEOnly = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2026-01-01T00:00:00Z",
    "creators": ["Tool: syft-0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "libfoo",
      "versionInfo": "1.0.0",
      "externalRefs": [
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe23Type",
          "referenceLocator": "cpe:2.3:a:example:libfoo:1.0.0:*:*:*:*:*:*:*"
        }
      ]
    }
  ]
}
`)

var cdxTwoCompsOneWithPURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-1",
      "name": "libfoo",
      "version": "1.0.0",
      "purl": "pkg:golang/github.com/example/libfoo@v1.0.0"
    },
    {
      "type": "library",
      "bom-ref": "comp-2",
      "name": "libbar",
      "version": "2.0.0"
    }
  ]
}
`)

func TestBSIV11CompOtherIdentifiers(t *testing.T) {
	ctx := context.Background()

	// cdxCompValidPURL has one component with a valid PURL (from fsct_test.go).
	t.Run("cdxWithPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Unique identifiers declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompPURLValid has one package with a valid PURL externalRef (from fsct_test.go).
	t.Run("spdxWithPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLValid, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Unique identifiers declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX component with CPE only (no PURL)
	t.Run("cdxWithCPEOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithCPEOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Unique identifiers declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX package with CPE externalRef only (no PURL)
	t.Run("spdxWithCPEOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithCPEOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Unique identifiers declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxTwoCompWithValidPURL has 2 components both with valid PURLs (from fsct_test.go).
	t.Run("cdxMultipleCompsAllWithPURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithValidPURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Unique identifiers declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLAbsent has one component with no PURL and no CPE
	t.Run("cdxNoIdentifiers", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare additional unique identifiers (optional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// spdxCompPURLAbsent has one package with no externalRefs
	t.Run("spdxNoIdentifiers", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare additional unique identifiers (optional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// cdxSBOMAuthor has no components
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 1 out of 2 components has a PURL
	t.Run("cdxPartialIdentifiers", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompsOneWithPURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompOtherIdentifiers(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare unique identifiers.", got.Desc)
		assert.False(t, got.Ignore)
	})
}
