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

package profiles

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cdxCompWithProperties = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-library",
      "version": "1.0.0",
      "properties": [
        {
          "name": "Foo",
          "value": "Bar"
        }
      ]
    }
  ]
}
`)

var cdxCompWithBSIFileProperties = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-library",
      "version": "1.0.0",
      "properties": [
        {
          "name": "bsi:component:filename",
          "value": "Bar"
        }
      ]
    }
  ]
}
`)

var cdxCompWithBSIExecutableFileProperties = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-library",
      "version": "1.0.0",
      "properties": [
        {
          "name": "bsi:component:executable",
          "value": "Bar"
        }
      ]
    }
  ]
}
`)

var cdxCompWithBSIArchiveFileProperties = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-library",
      "version": "1.0.0",
      "properties": [
        {
          "name": "bsi:component:archive",
          "value": "Bar"
        }
      ]
    }
  ]
}
`)

var cdxCompWithBSIStructuredFileProperties = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "acme-library",
      "version": "1.0.0",
      "properties": [
        {
          "name": "bsi:component:structured",
          "value": "Bar"
        }
      ]
    }
  ]
}
`)

func TestBSIV20CompProperties(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithProperties", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare filename", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithBSIFileProperties", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "filename declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithBSIExecutableFileProperties", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIExecutableFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "executable property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithBSIArchiveFileProperties", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIArchiveFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompArchiveProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "archive property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithBSIStructuredFileProperties", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIStructuredFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompStructuredProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "structured property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

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

// SPDX: one package with PackageFileName set (section 7.13).
var spdxPkgWithFilename = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-pkgfilename-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "packageFileName": "my-app-1.0.0.tar.gz"
    }
  ]
}
`)

// SPDX: one package without PackageFileName.
var spdxPkgWithoutFilename = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-nopkgfilename-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com"
    }
  ]
}
`)

// SPDX: two packages — one with PackageFileName, one without — for partial score.
var spdxTwoPkgsOneFilename = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-partialfilename-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "packageFileName": "my-app-1.0.0.tar.gz"
    },
    {
      "SPDXID": "SPDXRef-pkg2",
      "name": "libfoo",
      "versionInfo": "2.0.0",
      "downloadLocation": "https://example.com/libfoo"
    }
  ]
}
`)

// SPDX: package with PrimaryPackagePurpose = APPLICATION (executable).
var spdxPkgWithApplicationPurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-application-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "primaryPackagePurpose": "APPLICATION"
    }
  ]
}
`)

// SPDX: package with PrimaryPackagePurpose = ARCHIVE.
var spdxPkgWithArchivePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-archive-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "my-archive",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "primaryPackagePurpose": "ARCHIVE"
    }
  ]
}
`)

// SPDX: package with PrimaryPackagePurpose = SOURCE (structured).
var spdxPkgWithSourcePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-source-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "my-lib-src",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "primaryPackagePurpose": "SOURCE"
    }
  ]
}
`)

// SPDX: package with PrimaryPackagePurpose = LIBRARY (not executable/archive/structured).
var spdxPkgWithLibraryPurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-library-001",
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
      "primaryPackagePurpose": "LIBRARY"
    }
  ]
}
`)

// SPDX: two packages — one APPLICATION, one LIBRARY — partial executable score.
var spdxTwoPkgsOneApplication = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-partial-exec-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-pkg1",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com",
      "primaryPackagePurpose": "APPLICATION"
    },
    {
      "SPDXID": "SPDXRef-pkg2",
      "name": "libfoo",
      "versionInfo": "2.0.0",
      "downloadLocation": "https://example.com/libfoo",
      "primaryPackagePurpose": "LIBRARY"
    }
  ]
}
`)

// ===========================================================================
// TestBSIV20CompFilename
// ===========================================================================

func TestBSIV20CompFilename(t *testing.T) {
	ctx := context.Background()

	// CDX: no components → score 0, not ignored (required field).
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX: component has bsi:component:filename property set → score 10.
	t.Run("cdxWithFilenameProperty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "filename declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: package has PackageFileName set → score 10.
	t.Run("spdxPkgWithFilename", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "PackageFileName declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: package has no PackageFileName → score 0.
	t.Run("spdxPkgWithoutFilename", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithoutFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare PackageFileName.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: 1 of 2 packages has PackageFileName → partial score.
	t.Run("spdxTwoPkgsOneFilename", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxTwoPkgsOneFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompFilename(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare PackageFileName.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// SPDX: primary component that CONTAINS two sub-components (statically embedded).
// v2.0.0 recognises CONTAINS as a dependency type (BSI §3.2.4).
// SPDX supports CONTAINS as a first-class relationship type.
var spdxWithContainsDependencies = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-app-sbom",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "urn:uuid:bsiv20-spdx-contains-001",
  "creationInfo": {
    "creators": ["Tool: sbomqs"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-my-app",
      "name": "my-app",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com/my-app"
    },
    {
      "SPDXID": "SPDXRef-libfoo",
      "name": "libfoo",
      "versionInfo": "1.0.0",
      "downloadLocation": "https://example.com/libfoo"
    },
    {
      "SPDXID": "SPDXRef-libbar",
      "name": "libbar",
      "versionInfo": "2.0.0",
      "downloadLocation": "https://example.com/libbar"
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
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-libfoo"
    },
    {
      "spdxElementId": "SPDXRef-my-app",
      "relationshipType": "CONTAINS",
      "relatedSpdxElement": "SPDXRef-libbar"
    }
  ]
}
`)

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

	// v2.0-specific: CONTAINS relationships (statically embedded components)
	// must also be traversed during dependency resolution (BSI §3.2.4).
	t.Run("spdxWithContainsDependencies", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithContainsDependencies, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "Dependencies are recursively declared and structurally complete.", got.Desc)
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

// CDX: two components — one with SHA-512, one without — for partial score test.
// No metadata.component so only the two entries in components[] are counted.
var cdxTwoCompsOneSHA512 = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv20-cdx-twohash-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-a",
      "name": "lib-with-hash",
      "version": "1.0.0",
      "hashes": [
        {
          "alg": "SHA-512",
          "content": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-b",
      "name": "lib-without-hash",
      "version": "2.0.0"
    }
  ]
}
`)

func TestBSIV20CompDeployableHash(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxPrimaryCompWithSHA512HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA512HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SHA-512 hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithSHA512Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithSHA512Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SHA-512 hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithSHA256Hash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithSHA256Hash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithMD5HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithMD5HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithSHA1HashOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithSHA1HashOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxPrimaryCompWithMultipleHashesIncludingSHA256", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxPrimaryCompWithMultipleHashesIncludingSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxPrimaryCompWithMultipleHashesIncludingSHA256", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPrimaryCompWithMultipleHashesIncludingSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 1 of 2 components has SHA-512 — partial score
	t.Run("cdxTwoCompsOneSHA512", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompsOneSHA512, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare a SHA-512 deployable hash.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// No components at all
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found in SBOM.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompExecutableProperty
// ===========================================================================

func TestBSIV20CompExecutableProperty(t *testing.T) {
	ctx := context.Background()

	// CDX: no components → score 0, not ignored (required field).
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX: component has bsi:component:executable property set → score 10.
	t.Run("cdxWithExecutableProperty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIExecutableFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "executable property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: PrimaryPackagePurpose = APPLICATION → score 10.
	t.Run("spdxPkgWithApplicationPurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithApplicationPurpose, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "executable property declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: PrimaryPackagePurpose = LIBRARY → score 0 (not executable).
	t.Run("spdxPkgWithNonExecutablePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithLibraryPurpose, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare executable property via PrimaryPackagePurpose.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: 1 of 2 packages has APPLICATION purpose → partial score.
	t.Run("spdxTwoPkgsOneApplication", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxTwoPkgsOneApplication, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompExecutableProperty(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare executable property via PrimaryPackagePurpose.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompArchiveProperty
// ===========================================================================

func TestBSIV20CompArchiveProperty(t *testing.T) {
	ctx := context.Background()

	// CDX: no components → score 0, not ignored (required field).
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompArchiveProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX: component has bsi:component:archive property set → score 10.
	t.Run("cdxWithArchiveProperty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIArchiveFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompArchiveProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "archive property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: PrimaryPackagePurpose = ARCHIVE → score 10.
	t.Run("spdxPkgWithArchivePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithArchivePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompArchiveProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "archive property declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: PrimaryPackagePurpose = LIBRARY → score 0 (not an archive).
	t.Run("spdxPkgWithNonArchivePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithLibraryPurpose, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompArchiveProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare archive property via PrimaryPackagePurpose.", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV20CompStructuredProperty
// ===========================================================================

func TestBSIV20CompStructuredProperty(t *testing.T) {
	ctx := context.Background()

	// CDX: no components → score 0, not ignored (required field).
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompStructuredProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found", got.Desc)
		assert.False(t, got.Ignore)
	})

	// CDX: component has bsi:component:structured property set → score 10.
	t.Run("cdxWithStructuredProperty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithBSIStructuredFileProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompStructuredProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "structured property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: PrimaryPackagePurpose = SOURCE → score 10.
	t.Run("spdxPkgWithSourcePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithSourcePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompStructuredProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "structured property declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX: PrimaryPackagePurpose = LIBRARY → score 0 (not structured source).
	t.Run("spdxPkgWithNonStructuredPurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxPkgWithLibraryPurpose, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompStructuredProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare structured property via PrimaryPackagePurpose.", got.Desc)
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
		assert.Equal(t, "no components found in SBOM.", got.Desc)
		assert.True(t, got.Ignore) // Additional field: prerequisite condition not met
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
		assert.Equal(t, "no components found in SBOM.", got.Desc)
		assert.True(t, got.Ignore) // Optional field: prerequisite condition not met
	})
}

// ===========================================================================
// TestBSIV20CompSourceHash
// ===========================================================================

func TestBSIV20CompSourceHash(t *testing.T) {
	ctx := context.Background()

	// cdxCompWithVCSAndSHA256 has a VCS ref + SHA-256 hash (reused from bsiv11 fixtures)
	t.Run("cdxWithSourceHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithVCSAndSHA256, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// spdxCompWithVerificationCode has a PackageVerificationCode
	t.Run("spdxWithVerificationCode", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithVerificationCode, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source hash declared for all components.", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxCompPURLAbsent has a component with no source refs at all
	t.Run("cdxNoSourceHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompPURLAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source hash (optional field).", got.Desc)
		assert.True(t, got.Ignore)
	})

	// cdxSBOMAuthor has no components at all
	t.Run("cdxNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthor, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV20CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found in SBOM.", got.Desc)
		assert.True(t, got.Ignore)
	})
}
