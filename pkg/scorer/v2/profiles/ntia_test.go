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
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
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
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "supplier": "Organization: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    }
  ]
}
`)

var cdxCompSupplierWithNameAndURL = []byte(`
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

var cdxCompSupplierWithNameAndEmail = []byte(`
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

var cdxCompSupplierWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "SPDXID": "SPDXRef-AcmeLib",
      "name": "Acme Library",
      "versionInfo": "3.0",
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

var cdxCompManufacturerWithNameAndURL = []byte(`
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

var cdxCompManufacturerWithNameAndEmail = []byte(`
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

var cdxCompManufacturerWithName = []byte(`
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
        "name": "Acme, Inc."
      }
    }
  ]
}
`)

var cdxCompManufacturerAbsent = []byte(`
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

var cdxCompManufacturerWithEmptyName = []byte(`
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
        "name": ""
      }
    }
  ]
}
`)

var cdxCompManufacturerWithWhiteSpaceName = []byte(`
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
        "name": "  "
      }
    }
  ]
}
`)

var cdxCompManufacturerMissing = []byte(`
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
      "manufacturer": {}
    }
  ]
}
`)

func TestNTIACompSupplier(t *testing.T) {
	ctx := context.Background()

	// cdxCompSupplierWithNameURLAndEmail
	t.Run("cdxCompSupplierWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierAsPersonWithNameAndEmail
	t.Run("spdxCompSupplierAsPersonWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsPersonWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierAsOrganizationWithNameAndEmail
	t.Run("spdxCompSupplierAsOrganizationWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAsOrganizationWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithNameAndURL
	t.Run("cdxCompSupplierWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithPersonEmail
	t.Run("spdxCompSupplierWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithOrganizationEmail
	t.Run("spdxCompSupplierWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithNameAndEmail
	t.Run("cdxCompSupplierWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithName
	t.Run("cdxCompSupplierWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithPersonName
	t.Run("spdxCompSupplierWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithOrganizationName
	t.Run("spdxCompSupplierWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierAbsent
	t.Run("cdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierAbsent
	t.Run("spdxCompSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithEmptyName
	t.Run("cdxCompSupplierWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompSupplierWithPersonNameEmpty
	t.Run("spdxCompSupplierWithPersonNameEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompSupplierWithPersonNameEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompSupplierWithWhiteSpaceName
	t.Run("cdxCompSupplierWithWhiteSpaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSupplierWithWhiteSpaceName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithNameURLAndEmail
	t.Run("cdxCompManufacturerWithNameURLAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameURLAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithNameAndURL
	t.Run("cdxCompManufacturerWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithNameAndEmail
	t.Run("cdxCompManufacturerWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithName
	t.Run("cdxCompManufacturerWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerAbsent
	t.Run("cdxCompManufacturerAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithEmptyName
	t.Run("cdxCompManufacturerWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerWithWhiteSpaceName
	t.Run("cdxCompManufacturerWithWhiteSpaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerWithWhiteSpaceName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompManufacturerMissingName
	t.Run("cdxCompManufacturerMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompManufacturerMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})
}

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

var spdxSBOMAuthorWithPersonNameAndEmail = []byte(`
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

var spdxSBOMCreatorMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": []
  },
  "packages": []
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

var cdxSBOMAuthorsWithNameAndEmailEmptyString = []byte(`
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

var spdxSBOMCreatorsWithEmptyString = []byte(`
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

var cdxSBOMToolWithNameAndVersion = []byte(`
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
          "group": "Awesome Vendor",
          "name": "Awesome Tool",
          "version": "9.1.2"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithNameAndVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: Awesome Tool-9.1.2"
    ]
  },
  packages: []
}
`)

var cdxSBOMToolWithName = []byte(`
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
          "group": "Awesome Vendor",
          "name": "Awesome Tool"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: Awesome Tool"
    ]
  },
  packages: []
}
`)

var cdxSBOMToolWithVersion = []byte(`
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
          "group": "Awesome Vendor",
          "version": "9.1.2"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: -9.1.2"
    ]
  },
  packages: []
}
`)

var cdxSBOMToolAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMToolAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {},
  "packages": []
}
`)

var cdxSBOMToolMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {}
  },
  "components": []
}
`)

var spdxSBOMToolMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": []
  },
  "packages": []
}
`)

var spdxSBOMToolWithEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: "
      ]
  },
  "packages": []
}
`)

var cdxSBOMDeprecatedToolWithNameAndVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "Awesome Vendor",
        "name": "Awesome Tool",
        "version": "9.1.2"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "Awesome Vendor",
        "name": "Awesome Tool"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolWithVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "Awesome Vendor",
        "version": "9.1.2"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolWithNameAndVersionEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [
      {
        "vendor": "",
        "version": ""
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMDeprecatedToolAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMToolWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "tools": []
  },
  "components": []
}
`)

var spdxSBOMToolWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": {}
  },
  "packages": []
}
`)

// fallback aythor as supplier, when not author or tool is present
var cdxSBOMSupplierWithNameAndURL = []byte(`
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

var cdxSBOMSupplierWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "Acme, Inc."
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierWithURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {}
  },
  "components": []
}
`)

var cdxSBOMSupplierAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMSupplierWithNameEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": ""
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierWithURLEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "url": [
        ""
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierWithNameWhitespace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1, 
  "metadata": {
    "supplier": {
      "name": "   "
    }
  }
}
`)

var cdxSBOMSupplierWithWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": []
  },
  "components": []
}
`)

// / fallback to manufactyrer
var cdxSBOMManufacturerWithNameAndURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMManufacturerWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "name": "Acme, Inc."
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureWithURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureMissing = []byte(`
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

var cdxSBOMManufactureAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMManufactureWithNameEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "name": ""
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureWithURLEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": {
      "url": [
        ""
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMManufactureWithNameWhitespace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1, 
  "metadata": {
    "manufacture": {
      "name": "   "
    }
  }
}
`)

var cdxSBOMManufactureWithWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "manufacture": []
  },
  "components": []
}
`)

func TestNTIASBOMAuthor(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMAuthorWithNameAndEmail
	t.Run("cdxSBOMAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonNameAndEmail
	t.Run("spdxSBOMAuthorWithPersonNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationNameAndEmail
	t.Run("spdxSBOMAuthorWithOrganizationNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithEmail
	t.Run("cdxSBOMAuthorWithEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonEmail
	t.Run("spdxSBOMAuthorWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationEmail
	t.Run("spdxSBOMAuthorWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorWithName
	t.Run("cdxSBOMAuthorWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithPersonName
	t.Run("spdxSBOMAuthorWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorWithOrganizationName
	t.Run("spdxSBOMAuthorWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsAbsent
	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorAbsent
	t.Run("spdxSBOMAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorMissing
	t.Run("cdxSBOMAuthorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMCreatorMissing
	t.Run("spdxSBOMCreatorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorPersonMissing
	t.Run("spdxSBOMAuthorPersonMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorPersonMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorOrganizationMissing
	t.Run("spdxSBOMAuthorOrganizationMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorOrganizationMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithNameAndEmailEmptyString
	t.Run("cdxSBOMAuthorsWithNameAndEmailEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithNameAndEmailEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMCreatorsWithEmptyString
	t.Run("spdxSBOMCreatorsWithEmptyString", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMCreatorsWithEmptyString, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMAuthorsWithEmptyArray
	t.Run("cdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsWithEmptyArrayObject
	t.Run("cdxSBOMAuthorsWithEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMAuthorsWithEmptyArray
	t.Run("spdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
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

	// cdxSBOMToolWithNameAndVersion
	t.Run("cdxSBOMToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithNameAndVersion
	t.Run("spdxSBOMToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolWithName
	t.Run("cdxSBOMToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool with name only", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithName
	t.Run("spdxSBOMToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool with name only", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolWithVersion
	t.Run("cdxSBOMToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool with version only", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithVersion
	t.Run("spdxSBOMToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool with version only", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolAbsent
	t.Run("cdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolAbsent
	t.Run("spdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolMissing
	t.Run("cdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolMissing
	t.Run("spdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWithEmptyString
	t.Run("spdxSBOMToolWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithNameAndVersion
	t.Run("cdxSBOMDeprecatedToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithName
	t.Run("cdxSBOMDeprecatedToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool with name only", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithVersion
	t.Run("cdxSBOMDeprecatedToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from SBOM tool with version only", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolWithNameAndVersionEmptyString
	t.Run("cdxSBOMDeprecatedToolWithNameAndVersionEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithNameAndVersionEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMDeprecatedToolAbsent
	t.Run("cdxSBOMDeprecatedToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMToolWrongType
	t.Run("cdxSBOMToolWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMToolWrongType
	t.Run("spdxSBOMToolWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMSupplierWithNameAndURL(fallback when neither author not tool is present)
	t.Run("cdxSBOMSupplierWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithName
	t.Run("cdxSBOMSupplierWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithURL
	t.Run("cdxSBOMSupplierWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from supplier (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierMissing
	t.Run("cdxSBOMSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierAbsent
	t.Run("cdxSBOMSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithNameEmptyString
	t.Run("cdxSBOMSupplierWithNameEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithURLEmptyString
	t.Run("cdxSBOMSupplierWithURLEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithURLEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithNameWhitespace
	t.Run("cdxSBOMSupplierWithNameWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMSupplierWithWrongType
	t.Run("cdxSBOMSupplierWithWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMManufacturerWithNameAndURL
	t.Run("cdxSBOMManufacturerWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from manufacturer (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufacturerWithName
	t.Run("cdxSBOMManufacturerWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerWithName, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from manufacturer (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithURL
	t.Run("cdxSBOMManufactureWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author inferred from manufacturer (fallback)", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureMissing
	t.Run("cdxSBOMManufactureMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureAbsent
	t.Run("cdxSBOMManufactureAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithNameEmptyString
	t.Run("cdxSBOMManufactureWithNameEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithNameEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithURLEmptyString
	t.Run("cdxSBOMManufactureWithURLEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithURLEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithNameWhitespace
	t.Run("cdxSBOMManufactureWithNameWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithNameWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add SBOM author information", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMManufactureWithWrongType
	t.Run("cdxSBOMManufactureWithWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithWrongType, sbom.Signature{})
		require.Error(t, err)
	})

}

var cdxCompWithPrimaryRelationships = []byte(`
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app-1.0",
      "dependsOn": [
        "library-a",
        "library-b"  
      ]
    },
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxCompWithPrimaryRelationships = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-App"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibA"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibB"
    },
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }
  ]
}
`)

var cdxCompWithNoPrimaryRelationships = []byte(`
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxCompWithNoPrimaryRelationships = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-App"
    },
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    },
    {
      "spdxElementId": "SPDXRef-LibA",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }

  ]
}
`)

var cdxCompWithPrimaryComponentMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "bom-ref": "library-a",
      "type": "library",
      "name": "library-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxCompWithPrimaryComponentMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    },
    {
      "spdxElementId": "SPDXRef-LibA",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }
  ]
}
`)

var cdxCompWithPrimaryRelationshipsAndDeclaredRelationships = []byte(`
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app-1.0",
      "dependsOn": [
        "library-a",
        "library-b"  
      ]
    },
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": ["app"]
    }
  ]
}
`)

var cdxCompWithPrimaryDeclaredRelationshipsComplete = []byte(`
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": ["app-1.0"]
    }
  ]
}
`)

var cdxCompWithPrimaryDeclaredRelationshipsUnknown = []byte(`
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "unknown",
      "dependencies": ["app-1.0"]
    }
  ]
}
`)

var cdxCompWithPrimaryDeclaredRelationshipsIncomplete = []byte(`
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ],
  "compositions": [
    {
      "aggregate": "incomplete",
      "dependencies": ["app-1.0"]
    }
  ]
}
`)

var cdxCompWithRelationshipsAbsent = []byte(`
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0"
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ]
}
`)

func TestNTIACompDependencies(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 top-level dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 top-level dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component has no top-level relationships and nor declare relationships completeness", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithNoPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component has no top-level relationships and nor declare relationships completeness", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "define primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "define primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryRelationshipsAndDeclaredRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryRelationshipsAndDeclaredRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 top-level dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryDeclaredRelationshipsComplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryDeclaredRelationshipsComplete, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component has no relationships but decalred (relationships completeness: complete)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryDeclaredRelationshipsUnknown", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryDeclaredRelationshipsUnknown, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "primary component has no relationships but decalred (relationships completeness: unknown)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithPrimaryDeclaredRelationshipsIncomplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryDeclaredRelationshipsIncomplete, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component has no relationships but decalred (relationships completeness: incomplete)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithRelationshipsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithRelationshipsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary component has no top-level relationships and nor declare relationships completeness", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxSBOMWithCompleteFields = []byte(`
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
          "group": "Awesome Vendor",
          "name": "Awesome Tool",
          "version": "9.1.2"
        }
      ]
    },
    "authors": [
      {
        "bom-ref": "author-1",
        "name": "Samantha Wright",
        "email": "samantha.wright@example.com"
      }
    ],
    "supplier": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    },
    "manufacture": {
      "name": "Acme, Inc.",
      "url": [
        "https://example.com"
      ]
    },
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
      "version": "1.0.0",
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
    },
    {
      "bom-ref": "library-b",
      "type": "library",
      "name": "library-b",
      "version": "1.0.0",
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
    },
    {
      "bom-ref": "library-c",
      "type": "library",
      "name": "library-c",
      "version": "1.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app-1.0",
      "dependsOn": [
        "library-a",
        "library-b"  
      ]
    },
    {
      "ref": "library-a",
      "dependsOn": []
    },
    {
      "ref": "library-b",
      "dependsOn": [
        "library-c"
      ]
    }
  ]
}
`)

var spdxSBOMWithCompleteFields = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": [
      "Person: Samantha Wright (samantha.wright@example.com)",
      "Tool: Awesome Tool-9.1.2"
    ]
  },

  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0",
      "supplier": "Person: Samantha Wright (samantha.wright@example.com)",
      "homepage" : "http://ftp.gnu.org/gnu/glibc"
    },
    {
      "SPDXID": "SPDXRef-LibA",
      "name": "library-a",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibB",
      "name": "library-b",
      "versionInfo": "1.0.0"
    },
    {
      "SPDXID": "SPDXRef-LibC",
      "name": "library-c",
      "versionInfo": "1.0.0"
    }
  ],

  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-App"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibA"
    },
    {
      "spdxElementId": "SPDXRef-App",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibB"
    },
    {
      "spdxElementId": "SPDXRef-LibB",
      "relationshipType": "DEPENDS_ON",
      "relatedSpdxElement": "SPDXRef-LibC"
    }
  ]
}
`)

func TestNTIAComplete(t *testing.T) {
	ctx := context.Background()

	// --- 1. TEST DEPENDENCY RELATIONSHIPS ----
	// cdxSBOMWithCompleteFields
	t.Run("cdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 top-level dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMWithCompleteFields
	t.Run("spdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary component declares 2 top-level dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	// --- 2. TEST SBOM Author FIELDS ----
	// cdxSBOMWithCompleteFields
	t.Run("cdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMWithCompleteFields
	t.Run("spdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIASBOMWithAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM author declared explicitly", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 3. TEST Component Supplier FALLBACK ----
	t.Run("cdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxSBOMWithCompleteFields
	t.Run("spdxSBOMWithCompleteFields", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithCompleteFields, sbom.Signature{})
		require.NoError(t, err)

		got := NTIACompWithSupplier(doc)

		assert.InDelta(t, 2.5, got.Score, 1e-9)
		assert.Equal(t, "add to 3 components", got.Desc)
		assert.False(t, got.Ignore)
	})
}
