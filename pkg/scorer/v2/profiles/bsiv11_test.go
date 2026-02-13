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
        "email": "samantha.wright@example.com"
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
      "Person: (samantha.wright@example.com)"
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

func TestBSIV11SBOMCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the authors field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPersonAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the authors field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the authors field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPersonAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the authors field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator information is present, but only valid email or URL are accepted.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPersonAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator information is present, but only valid email or URL are accepted.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMOrganizationAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMOrganizationAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the authors field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMOrganizationAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMOrganizationAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the authors field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMOrganizationAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMOrganizationAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator information is present, but only valid email or URL are accepted.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMCreationInfoMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreationInfoMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator information is present, but only valid email or URL are accepted.", got.Desc)
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
		assert.Equal(t, "SBOM creator is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator information is present, but only valid email or URL are accepted.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is missing.", got.Desc)
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
		assert.Equal(t, "SBOM creator is provided using the supplier field (fallback).", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the supplier field (fallback).", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the supplier field (fallback).", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator information is present, but only valid email or URL are accepted.", got.Desc)
		assert.False(t, got.Ignore)
	})

	//
	t.Run("cdxSBOMManufacturer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturer, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the manufacturer field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMManufacturerURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator is provided using the manufacturer field.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMManufacturerContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "author with contact present", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMManufacturerNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator information is present, but only valid email or URL are accepted.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

//

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
            "email": "professional.services@example.com"
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

func TestBSIV11CompCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompOrganizationSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompOrganizationSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompOrganizationSupplierEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompOrganizationSupplierEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompOrganizationSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompOrganizationSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplierEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplierEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompAuthorEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
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
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSupplierNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	//
	t.Run("cdxCompManufacturer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturer, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerURLOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerURLOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerContactEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerContactEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompManufacturerNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV11CompCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
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

func TestBSIV11CompDependencies(t *testing.T) {
	ctx := context.Background()

	// cdxWithCompleteDependencies
	t.Run("cdxWithCompleteDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithCompleteDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithCompleteReplationship
	t.Run("spdxWithCompleteReplationship", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithCompleteReplationship, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingDependenciesSection
	t.Run("cdxWithMissingDependenciesSection", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingDependenciesSection, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingRelationships
	t.Run("spdxWithMissingRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingSourceDependencyInSBOM
	t.Run("cdxWithMissingSourceDependencyInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingSourceDependencyInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency source references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingSourceRelationshipInSBOM
	t.Run("spdxWithMissingSourceRelationshipInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingSourceRelationshipInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency source references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingTargetDependencyInSBOM
	t.Run("cdxWithMissingTargetDependencyInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingTargetDependencyInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency target references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingTargetRelationshipInSBOM
	t.Run("spdxWithMissingTargetRelationshipInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingTargetRelationshipInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency target references undefined component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithOrphanComponentInSBOM
	t.Run("cdxWithOrphanComponentInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithOrphanComponentInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "Some components are not reachable from the primary component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithOrphanComponentInSBOM
	t.Run("spdxWithOrphanComponentInSBOM", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithOrphanComponentInSBOM, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "Some components are not reachable from the primary component.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithPrimaryCompDepenencyMissingButOthersPresent
	t.Run("cdxWithPrimaryCompDepenencyMissingButOthersPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPrimaryCompDepenencyMissingButOthersPresent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component does not declare its dependencies.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithPrimaryCompRelationshipMissingButOthersPresent
	t.Run("spdxWithPrimaryCompRelationshipMissingButOthersPresent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithPrimaryCompRelationshipMissingButOthersPresent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component does not declare its dependencies.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxWithMissingDependencies
	t.Run("cdxWithMissingDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxWithMissingRelationship
	t.Run("spdxWithMissingRelationship", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithMissingRelationship, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompWithPrimaryCompMissing
	t.Run("cdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompWithPrimaryCompMissing
	t.Run("spdxCompWithPrimaryCompMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryCompMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Primary component is missing.", got.Desc)
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

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithLicenseExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithLicenseExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithCustomLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithCustomLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithCustomLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithCustomLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoneLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoneLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Licence information is missing for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithNoneLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoneLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Licence information is missing for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoAssertionLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoAssertionLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Licence information is missing for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithNoAssertionLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoAssertionLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Licence information is missing for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithInvalidLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 1 have Licence information but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithInvalidLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithInvalidLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 1 have Licence information but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithInvalidExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 1 have Licence information but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithInvalidExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithInvalidExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 1 have Licence information but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithMixedLicenses", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMixedLicenses, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithMixedLicenses", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMixedLicenses, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 1 have Licence information but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithInvalidLicenseSPDXID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInvalidLicenseSPDXID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 1 have Licence information but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithInvalidLicenseSPDXID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithInvalidLicenseSPDXID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 1 have Licence information but invalid.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryCompConcludedLicenseIDMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryCompConcludedLicenseIDMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 2 have valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryCompConcludedLicenseMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryCompConcludedLicenseMissing, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Licence information is missing for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedDeprecatedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedDeprecatedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedDeprecatedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedDeprecatedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredDeprecatedLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredDeprecatedLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredDeprecatedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredDeprecatedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithConcludedRestrictiveLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithConcludedRestrictiveLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithConcludedRestrictiveLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithConcludedRestrictiveLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithDeclaredRestrictiveLicenseID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDeclaredRestrictiveLicenseID, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithDeclaredRestrictiveLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithDeclaredRestrictiveLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "All components declare valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompLicenseAbsentForNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompLicenseAbsentForNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 2 have valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompLicenseAbsentForNormalComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompLicenseAbsentForNormalComponent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1 components out of 2 have valid licence information.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompLicenseEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompLicenseEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Licence information is missing for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompLicenseEmptyObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompLicenseEmptyObject, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV1CompLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Licence information is missing for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

}
