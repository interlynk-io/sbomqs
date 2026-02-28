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

// SPDX: primary component with a SHA-512 checksum.
// v2.0.0 requires SHA-512 for the deployable hash; this is the SPDX pass case.
var spdxPrimaryCompWithSHA512Hash = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-sha512-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com/my-app",
      "checksums": [
        {
          "algorithm": "SHA512",
          "checksumValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
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

// CDX: one component with MIT licence acknowledged as "concluded".
var bsiv20CdxCompWithConcludedMITLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv20-cdx-concl-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-concl-1",
      "name": "libfoo",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "MIT",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

// SPDX: one package with PackageLicenseConcluded = MIT.
var bsiv20SpdxCompWithConcludedMITLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-concl-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "libfoo",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "licenseConcluded": "MIT"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-pkg1"
    }
  ]
}
`)

// CDX: one component with Apache-2.0 acknowledged as "declared".
var bsiv20CdxCompWithDeclaredApacheLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv20-cdx-decl-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-decl-1",
      "name": "libbar",
      "version": "2.0.0",
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

// SPDX: one package with PackageLicenseDeclared = Apache-2.0.
var bsiv20SpdxCompWithDeclaredApacheLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-decl-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "libbar",
      "versionInfo": "2.0.0",
      "downloadLocation": "https://example.com",
      "licenseDeclared": "Apache-2.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-pkg1"
    }
  ]
}
`)

// CDX: one component with NOASSERTION acknowledged as "concluded"
var bsiv20CdxCompWithNoAssertionConcludedLicense = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv20-cdx-concl-noassert-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-noassert-1",
      "name": "libfoo",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "NOASSERTION",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

// SPDX: one package with NOASSERTION as PackageLicenseConcluded.
var bsiv20SpdxCompWithNoAssertionConcludedLicense = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-concl-noassert-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "libfoo",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "licenseConcluded": "NOASSERTION"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relationshipType": "DESCRIBES",
      "relatedSpdxElement": "SPDXRef-pkg1"
    }
  ]
}
`)

// CDX: one component with no licenses at all
var bsiv20CdxCompWithNoLicenses = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv20-cdx-noLic-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-noLic-1",
      "name": "unlicensed-lib",
      "version": "0.1.0"
    }
  ]
}
`)

// ===========================================================================
// TestBSIV20SBOMCreator
// ===========================================================================

func TestBSIV20SBOMCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPersonAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator contact(email) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMCreator(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creator present but lacks valid email or URL", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20SBOMCreationTimestamp
// ===========================================================================

func TestBSIV20SBOMCreationTimestamp(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithValidTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMCreationTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is valid and RFC3339-compliant.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithValidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithValidTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMCreationTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is valid and RFC3339-compliant.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxWithInvalidTimestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithInvalidTimestamp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is not a valid RFC3339 (ISO-8601) timestamp.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithMissingTimestamp", func(t *testing.T) {
		// spdxSBOMPersonAuthor has no creationInfo.created field.
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM creation timestamp is missing", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompCreator
// ===========================================================================

func TestBSIV20CompCreator(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompAuthor", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompPersonSupplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompPersonSupplier, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompCreator(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "creator contact (email or URL) declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompName
// ===========================================================================

func TestBSIV20CompName(t *testing.T) {
	ctx := context.Background()

	// cdxCompAuthorAbsent has one named component.
	t.Run("cdxSingleNamedComponent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompName(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "component name declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has "components": [] → no components.
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompName(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declared in SBOM", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompVersion
// ===========================================================================

func TestBSIV20CompVersion(t *testing.T) {
	ctx := context.Background()

	// cdxCompAuthor has one component with version "9.1.1".
	t.Run("cdxAllComponentsHaveVersions", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompVersion(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "component version declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxWithMissingVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMissingVersion, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompVersion(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component version missing for 1 out of 1 components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompFilename
// ===========================================================================

func TestBSIV20CompFilename(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component filename check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("spdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component filename check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompDependencies
// ===========================================================================

func TestBSIV20CompDependencies(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithCompleteDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithCompleteDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxWithMissingDependenciesSection", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithMissingDependenciesSection, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "Dependency information is missing.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompAssociatedLicenses
// ===========================================================================

func TestBSIV20CompAssociatedLicenses(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithLicenseExpression", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithLicenseExpression, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompAssociatedLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "licence information declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithNoneLicense", func(t *testing.T) {
		// "expression": "NONE" is parsed as no licence by the SBOM interface.
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoneLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompAssociatedLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "licence info is missing for all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompDeployableHash
// ===========================================================================

func TestBSIV20CompDeployableHash(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxPrimaryCompWithSHA512HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA512HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component declares a valid SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithSHA512Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithSHA512Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component declares a valid SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithMD5HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithMD5HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithSHA1HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA1HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithMultipleHashesIncludingSHA256", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithMultipleHashesIncludingSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithMultipleHashesIncludingSHA256", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithMultipleHashesIncludingSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "primary deployable component must declare a SHA-512 hash.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompExecutableProperty
// ===========================================================================

func TestBSIV20CompExecutableProperty(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component executable property check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("spdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component executable property check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompArchiveProperty
// ===========================================================================

func TestBSIV20CompArchiveProperty(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompArchiveProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component archive property check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("spdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompArchiveProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component archive property check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompStructuredProperty
// ===========================================================================

func TestBSIV20CompStructuredProperty(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompStructuredProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component structured property check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("spdxAlwaysIgnored", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPersonAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompStructuredProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "component structured property check not yet supported by the SBOM interface", got.Desc)
		assert.True(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20SBOMURI
// ===========================================================================

func TestBSIV20SBOMURI(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithValidSerialNumber", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is declared.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithDocumentNamespaceURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithDocumentNamespace, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is declared.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxWithoutSerialNumber", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithoutSerialNumber, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20SBOMURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM-URI is missing (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompSourceURI
// ===========================================================================

func TestBSIV20CompSourceURI(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithVCSRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Source code URI declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompDeployableURI
// ===========================================================================

func TestBSIV20CompDeployableURI(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithDistributionRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithDistributionRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Executable URI declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthor has no components → No components found.
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompOtherIdentifiers
// ===========================================================================

func TestBSIV20CompOtherIdentifiers(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxWithCPEOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithCPEOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompOtherIdentifiers(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Unique identifiers declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxWithCPEOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithCPEOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompOtherIdentifiers(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Unique identifiers declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompConcludedLicenses
// ===========================================================================

func TestBSIV20CompConcludedLicenses(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxAllComponentsHaveConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20CdxCompWithConcludedMITLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompConcludedLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "concluded licence declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxAllPackagesHaveConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20SpdxCompWithConcludedMITLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompConcludedLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "concluded licence declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX: concluded licence is NOASSERTION.
	t.Run("cdxConcludedLicenseIsNoAssertion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20CdxCompWithNoAssertionConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompConcludedLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare concluded licence (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// SPDX: PackageLicenseConcluded = NOASSERTION.
	t.Run("spdxConcludedLicenseIsNoAssertion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20SpdxCompWithNoAssertionConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompConcludedLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare concluded licence (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("cdxNoConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20CdxCompWithNoLicenses, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompConcludedLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare concluded licence (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompConcludedLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found in SBOM.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompDeclaredLicenses
// ===========================================================================

func TestBSIV20CompDeclaredLicenses(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxAllComponentsHaveDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20CdxCompWithDeclaredApacheLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeclaredLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "declared licence declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxAllPackagesHaveDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20SpdxCompWithDeclaredApacheLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeclaredLicenses(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "declared licence declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxNoDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, bsiv20CdxCompWithNoLicenses, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeclaredLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare declared licence (optional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeclaredLicenses(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found in SBOM.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompSourceHash
// ===========================================================================

func TestBSIV20CompSourceHash(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxVCSSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSAndSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxVCSRefWithNoHashes", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components declare source hash (additional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// cdxSBOMAuthor has no components.
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "No components found.", got.Desc)
		assert.False(t, got.Ignore)
	})
}
