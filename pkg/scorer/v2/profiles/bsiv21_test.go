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

//
// TestBSIV21CompSourceCodeURI
//

// CDX: one component with a source-distribution externalReference with a URL.
var cdx21CompWithSourceDistributionURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-src-dist-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-src-dist",
      "name": "lib-with-source-dist",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "source-distribution",
          "url": "https://example.com/lib-1.0.0-sources.tar.gz"
        }
      ]
    }
  ]
}
`)

// CDX: one component with a vcs externalReference with a URL.
var cdx21CompWithVCSURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-vcs-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-vcs",
      "name": "lib-with-vcs",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/lib"
        }
      ]
    }
  ]
}
`)

// CDX: two components — one has source-distribution URL, one has vcs URL — both should pass.
var cdx21TwoCompsSourceDistAndVCS = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-src-vcs-002",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-src",
      "name": "lib-source-dist",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "source-distribution",
          "url": "https://example.com/lib-1.0.0-sources.tar.gz"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-vcs",
      "name": "lib-vcs",
      "version": "2.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/lib2"
        }
      ]
    }
  ]
}
`)

// CDX: two components — only one has a source-distribution or vcs URL — partial score.
var cdx21TwoCompsOneWithSourceCodeURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-partial-src-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-a",
      "name": "lib-with-source",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/liba"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-b",
      "name": "lib-without-source",
      "version": "2.0.0"
    }
  ]
}
`)

// CDX: one component with a distribution ext ref only (not source-distribution or vcs) — score 0.
var cdx21CompWithDistributionOnlyURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-no-src-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-dist-only",
      "name": "lib-dist-only",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://example.com/lib-1.0.0.jar"
        }
      ]
    }
  ]
}
`)

// SPDX 3.0: one component with software_sourceInfo (git URL) — score 10.0
var spdx3CompWithSourceInfo = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-with-source",
      "software_packageVersion": "1.0.0",
      "software_sourceInfo": "https://github.com/example/lib"
    }
  ]
}
`)

// SPDX 3.0: two components with software_sourceInfo — score 10.0
var spdx3TwoCompsWithSourceInfo = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "lib-with-source-1",
      "software_packageVersion": "1.0.0",
      "software_sourceInfo": "https://github.com/example/lib1"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "lib-with-source-2",
      "software_packageVersion": "2.0.0",
      "software_sourceInfo": "https://github.com/example/lib2"
    }
  ]
}
`)

// SPDX 3.0: two components — only one has software_sourceInfo — partial score
var spdx3TwoCompsOneWithSourceInfo = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "lib-with-source",
      "software_packageVersion": "1.0.0",
      "software_sourceInfo": "https://github.com/example/lib1"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "lib-without-source",
      "software_packageVersion": "2.0.0"
    }
  ]
}
`)

// SPDX 3.0: one component without software_sourceInfo — score 0
var spdx3CompWithoutSourceInfo = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-without-source",
      "software_packageVersion": "1.0.0"
    }
  ]
}
`)

// SPDX 3.0: software_SoftwareArtifact with externalRef (type SourceArtifact) linked via generates relationship.
var spdx3CompWithSourceArtifactExternalRef = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package", "SPDXRef-SourceArtifact"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-with-source-artifact",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_SoftwareArtifact",
      "spdxId": "SPDXRef-SourceArtifact",
      "software_primaryPurpose": "source",
      "externalRef": [
        {
          "type": "ExternalRef",
          "externalRefType": "SourceArtifact",
          "locator": "https://github.com/example/package/releases/download/v1.0.0/source.tar.gz"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-SourceArtifact",
      "to": ["SPDXRef-Package"],
      "relationshipType": "generates",
      "completeness": "complete"
    }
  ]
}
`)

func TestBSIV21CompSourceCodeURI(t *testing.T) {
	ctx := context.Background()

	// source-distribution ext ref with URL → score 10.0
	t.Run("sourceDistributionURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithSourceDistributionURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// vcs ext ref with URL → score 10.0
	t.Run("vcsURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithVCSURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// one comp with source-distribution, one with vcs → both pass → score 10.0
	t.Run("bothSourceDistAndVCS", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsSourceDistAndVCS, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 1 of 2 components has source code URL → partial score 5.0
	t.Run("partialSourceCodeURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsOneWithSourceCodeURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare source code URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// distribution ext ref only (wrong type) → score 0.0
	t.Run("distributionOnlyNoSourceURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithDistributionOnlyURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source code URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// no components → score 0.0
	t.Run("noComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithProperties, sbom.Signature{})
		require.NoError(t, err)

		// cdxCompWithProperties has 1 component with no ext refs
		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source code URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: software_sourceInfo with URL → score 10.0
	t.Run("spdx3SourceInfoURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithSourceInfo, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: two components with software_sourceInfo → score 10.0
	t.Run("spdx3BothSourceInfo", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsWithSourceInfo, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: 1 of 2 components has software_sourceInfo → partial score 5.0
	t.Run("spdx3PartialSourceInfo", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsOneWithSourceInfo, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare source code URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: no software_sourceInfo → score 0.0
	t.Run("spdx3NoSourceInfo", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithoutSourceInfo, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source code URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: software_SoftwareArtifact with externalRef SourceArtifact linked via generates → score 10.0
	t.Run("spdx3SourceArtifactExternalRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithSourceArtifactExternalRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceCodeURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

//
// TestBSIV21CompDownloadURI
//

// CDX: one component with a distribution-intake externalReference with a URL.
var cdx21CompWithDistributionIntakeURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-dist-intake-url-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-dist-intake",
      "name": "lib-dist-intake",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "distribution-intake",
          "url": "https://intake.example.com/lib-1.0.0.jar"
        }
      ]
    }
  ]
}
`)

// CDX: two components — one with distribution, one with distribution-intake — both should pass.
var cdx21TwoCompsDistAndDistIntake = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-dist-both-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-dist",
      "name": "lib-dist",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://example.com/lib-1.0.0.jar"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-dist-intake",
      "name": "lib-dist-intake",
      "version": "2.0.0",
      "externalReferences": [
        {
          "type": "distribution-intake",
          "url": "https://intake.example.com/lib-2.0.0.jar"
        }
      ]
    }
  ]
}
`)

// CDX: two components — only one has distribution or distribution-intake URL — partial score.

// SPDX 3.0: one component with software_downloadLocation — score 10.0
var spdx3CompWithDownloadLocation = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-with-download",
      "software_packageVersion": "1.0.0",
      "software_downloadLocation": "https://example.com/lib-1.0.0.jar"
    }
  ]
}
`)

var cdx21TwoCompsOneWithDeployableURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-dist-partial-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-a",
      "name": "lib-with-dist",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "distribution",
          "url": "https://example.com/lib-1.0.0.jar"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-b",
      "name": "lib-without-dist",
      "version": "2.0.0"
    }
  ]
}
`)

// SPDX 3.0: software_File with externalRef (type binaryArtifact) linked via hasDistributionArtifact.
var spdx3CompWithBinaryArtifactDownload = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package", "SPDXRef-File"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-with-binary-artifact",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File",
      "name": "lib-1.0.0.jar",
      "externalRef": [
        {
          "type": "ExternalRef",
          "externalRefType": "binaryArtifact",
          "locator": "https://example.com/lib-1.0.0.jar"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-File"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

func TestBSIV21CompDownloadURI(t *testing.T) {
	ctx := context.Background()

	// distribution ext ref with URL → score 10.0
	t.Run("distributionURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithDistributionOnlyURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "deployable form URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// distribution-intake ext ref with URL → score 10.0
	t.Run("distributionIntakeURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithDistributionIntakeURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "deployable form URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// one comp with distribution, one with distribution-intake → both pass → score 10.0
	t.Run("bothDistAndDistIntake", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsDistAndDistIntake, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "deployable form URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 1 of 2 components has deployable URL → partial score 5.0
	t.Run("partialDeployableURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsOneWithDeployableURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare deployable form URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// vcs ext ref only (wrong type for download URI) → score 0.0
	t.Run("vcsOnlyNoDeployableURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithVCSURL, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare deployable form URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// no ext refs → score 0.0
	t.Run("noExtRefs", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare deployable form URI", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: software_downloadLocation with URL → score 10.0
	t.Run("spdx3DownloadLocationURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithDownloadLocation, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "deployable form URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: software_File with externalRef (type binaryArtifact) linked via hasDistributionArtifact → score 10.0
	t.Run("spdx3BinaryArtifactExternalRef", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithBinaryArtifactDownload, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDownloadURI(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "deployable form URI declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

//
// TestBSIV21CompSourceHash
//

// CDX: one component with a source-distribution externalReference that has a hash.
var cdx21CompWithSourceDistributionHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-src-hash-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-src-hash",
      "name": "lib-src-hash",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "source-distribution",
          "url": "https://example.com/lib-1.0.0-sources.tar.gz",
          "hashes": [
            {
              "alg": "SHA-512",
              "content": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            }
          ]
        }
      ]
    }
  ]
}
`)

// CDX: one component with a vcs externalReference that has a hash.
var cdx21CompWithVCSHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-vcs-hash-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-vcs-hash",
      "name": "lib-vcs-hash",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/lib",
          "hashes": [
            {
              "alg": "SHA-512",
              "content": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12"
            }
          ]
        }
      ]
    }
  ]
}
`)

// CDX: two components — one has source-distribution hash, one has vcs hash — both pass.
var cdx21TwoCompsSrcHashAndVCSHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-src-vcs-hash-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-src",
      "name": "lib-src-hash",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "source-distribution",
          "url": "https://example.com/lib-1.0.0-sources.tar.gz",
          "hashes": [
            {
              "alg": "SHA-512",
              "content": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            }
          ]
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-vcs",
      "name": "lib-vcs-hash",
      "version": "2.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/lib2",
          "hashes": [
            {
              "alg": "SHA-512",
              "content": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
            }
          ]
        }
      ]
    }
  ]
}
`)

// CDX: two components — only one has a source code hash — partial score.
var cdx21TwoCompsOneWithSourceHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-src-hash-partial-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-a",
      "name": "lib-with-src-hash",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/example/liba",
          "hashes": [
            {
              "alg": "SHA-512",
              "content": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            }
          ]
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-b",
      "name": "lib-without-src-hash",
      "version": "2.0.0"
    }
  ]
}
`)

// CDX: source-distribution ext ref present but no hashes → score 0.
var cdx21CompWithSourceDistributionURLNoHash = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-src-nohash-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-src-nohash",
      "name": "lib-src-no-hash",
      "version": "1.0.0",
      "externalReferences": [
        {
          "type": "source-distribution",
          "url": "https://example.com/lib-1.0.0-sources.tar.gz"
        }
      ]
    }
  ]
}
`)

func TestBSIV21CompSourceHash(t *testing.T) {
	ctx := context.Background()

	// source-distribution ext ref with hash → score 10.0
	t.Run("sourceDistributionHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithSourceDistributionHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code hash declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// vcs ext ref with hash → score 10.0
	t.Run("vcsHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithVCSHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code hash declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// one comp with source-distribution hash, one with vcs hash → both pass → score 10.0
	t.Run("bothSourceDistAndVCSHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsSrcHashAndVCSHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "source code hash declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// 1 of 2 components has source code hash → partial score 5.0
	t.Run("partialSourceHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsOneWithSourceHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare source code hash", got.Desc)
		assert.False(t, got.Ignore)
	})

	// source-distribution ext ref present but no hash → score 0.0, Ignore=true (optional field)
	t.Run("sourceDistributionNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithSourceDistributionURLNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source code hash", got.Desc)
		assert.True(t, got.Ignore)
	})

	// no ext refs at all → score 0.0, Ignore=true (optional field)
	t.Run("noExtRefs", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source code hash", got.Desc)
		assert.True(t, got.Ignore)
	})
}

//
// TestBSIV21CompDistributionLicence (concluded licenses)
//

// CDX: one component with a license expression and acknowledgement=concluded
var cdx21CompWithExpressionConcluded = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-expr-concluded-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-expr-concluded",
      "name": "lib-expression-concluded",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "MIT",
          "acknowledgement": "concluded"
        }
      ]
    }
  ]
}
`)

// CDX: one component with a license ID and acknowledgement=concluded
var cdx21CompWithLicenseIDConcluded = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-id-concluded-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-id-concluded",
      "name": "lib-id-concluded",
      "version": "1.0.0",
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

// CDX: two components — one with expression concluded, one with ID concluded — both should pass
var cdx21TwoCompsExpressionAndIDConcluded = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-both-concluded-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-expr",
      "name": "lib-expression",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "MIT",
          "acknowledgement": "concluded"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-id",
      "name": "lib-id",
      "version": "2.0.0",
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

// CDX: one component with acknowledgement=declared (should NOT count as concluded)
var cdx21CompWithDeclaredOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-declared-only-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-declared",
      "name": "lib-declared",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "MIT",
            "acknowledgement": "declared"
          }
        }
      ]
    }
  ]
}
`)

// CDX: two components — one with concluded, one with declared only — partial score
var cdx21TwoCompsConcludedAndDeclared = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-mixed-ack-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-concluded",
      "name": "lib-concluded",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "MIT",
          "acknowledgement": "concluded"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-declared",
      "name": "lib-declared",
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

// CDX: license without acknowledgement (pre-1.6 style) — should NOT count as concluded
var cdx21CompWithLicenseNoAcknowledgement = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-no-ack-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-no-ack",
      "name": "lib-no-acknowledgement",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "MIT"
          }
        }
      ]
    }
  ]
}
`)

// CDX: custom license ref (not a valid SPDX ID) — should NOT pass
var cdx21CompWithCustomLicenseRef = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-custom-ref-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-custom",
      "name": "lib-custom-license",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "LicenseRef-Custom",
            "acknowledgement": "concluded"
          }
        }
      ]
    }
  ]
}
`)

// SPDX 3.0: one component with hasConcludedLicense relationship (MIT) — score 10.0
var spdx3CompWithConcludedLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package", "SPDXRef-License-MIT"],
      "profileConformance": ["core", "software", "licensing"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-with-concluded-license",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-MIT",
      "name": "MIT"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-License-MIT"],
      "relationshipType": "hasConcludedLicense"
    }
  ]
}
`)

// SPDX 3.0: two components with hasConcludedLicense — score 10.0
var spdx3TwoCompsWithConcludedLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2", "SPDXRef-License-MIT", "SPDXRef-License-Apache"],
      "profileConformance": ["core", "software", "licensing"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "lib-with-mit",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "lib-with-apache",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-MIT",
      "name": "MIT"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-Apache",
      "name": "Apache-2.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-License-MIT"],
      "relationshipType": "hasConcludedLicense"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package2",
      "to": ["SPDXRef-License-Apache"],
      "relationshipType": "hasConcludedLicense"
    }
  ]
}
`)

// SPDX 3.0: two components — only one has hasConcludedLicense — partial score
var spdx3TwoCompsOneWithConcludedLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2", "SPDXRef-License-MIT"],
      "profileConformance": ["core", "software", "licensing"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "lib-with-mit",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "lib-without-license",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-MIT",
      "name": "MIT"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-License-MIT"],
      "relationshipType": "hasConcludedLicense"
    }
  ]
}
`)

// SPDX 3.0: one component without hasConcludedLicense — score 0
var spdx3CompWithoutConcludedLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-without-concluded-license",
      "software_packageVersion": "1.0.0"
    }
  ]
}
`)

func TestBSIV21CompDistributionLicence(t *testing.T) {
	ctx := context.Background()

	// license expression with acknowledgement=concluded → score 10.0
	t.Run("expressionConcluded", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithExpressionConcluded, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "distribution licence (concluded) declared for all components", got.Desc)
	})

	// license ID with acknowledgement=concluded → score 10.0
	t.Run("licenseIDConcluded", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithLicenseIDConcluded, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "distribution licence (concluded) declared for all components", got.Desc)
	})

	// one comp with expression concluded, one with ID concluded → both pass → score 10.0
	t.Run("bothExpressionAndIDConcluded", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsExpressionAndIDConcluded, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "distribution licence (concluded) declared for all components", got.Desc)
	})

	// acknowledgement=declared only (no concluded) → score 0.0
	t.Run("declaredOnlyNoConcluded", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithDeclaredOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare distribution licence (concluded)", got.Desc)
	})

	// 1 of 2 components has concluded license → partial score 5.0
	t.Run("partialConcluded", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsConcludedAndDeclared, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare distribution licence (concluded)", got.Desc)
	})

	// license without acknowledgement (pre-1.6 style) → score 0.0
	t.Run("licenseNoAcknowledgement", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithLicenseNoAcknowledgement, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare distribution licence (concluded)", got.Desc)
	})

	// custom license ref (LicenseRef-Custom) with acknowledgement=concluded → score 10.0
	// LicenseRef-* is acceptable even if not a standard SPDX ID
	t.Run("customLicenseRefConcluded", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithCustomLicenseRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "distribution licence (concluded) declared for all components", got.Desc)
	})

	// no components → score 0.0
	t.Run("noComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:test", "version": 1, "components": []}`), sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found", got.Desc)
	})

	// SPDX 3.0: hasConcludedLicense relationship (MIT) → score 10.0
	t.Run("spdx3ConcludedLicenseMIT", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "distribution licence (concluded) declared for all components", got.Desc)
	})

	// SPDX 3.0: two components with hasConcludedLicense → score 10.0
	t.Run("spdx3BothConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsWithConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "distribution licence (concluded) declared for all components", got.Desc)
	})

	// SPDX 3.0: 1 of 2 components has hasConcludedLicense → partial score 5.0
	t.Run("spdx3PartialConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsOneWithConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare distribution licence (concluded)", got.Desc)
	})

	// SPDX 3.0: no hasConcludedLicense → score 0.0
	t.Run("spdx3NoConcludedLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithoutConcludedLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDistributionLicence(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare distribution licence (concluded)", got.Desc)
	})
}

//
// TestBSIV21CompOriginalLicences (declared licenses)
//

// CDX: one component with a license expression and acknowledgement=declared
var cdx21CompWithExpressionDeclared = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-expr-declared-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-expr-declared",
      "name": "lib-expression-declared",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "Apache-2.0",
          "acknowledgement": "declared"
        }
      ]
    }
  ]
}
`)

// CDX: one component with a license ID and acknowledgement=declared
var cdx21CompWithLicenseIDDeclared = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-id-declared-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-id-declared",
      "name": "lib-id-declared",
      "version": "1.0.0",
      "licenses": [
        {
          "license": {
            "id": "GPL-2.0",
            "acknowledgement": "declared"
          }
        }
      ]
    }
  ]
}
`)

// CDX: two components — one with expression declared, one with ID declared — both should pass
var cdx21TwoCompsExpressionAndIDDeclared = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-both-declared-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-expr",
      "name": "lib-expression",
      "version": "1.0.0",
      "licenses": [
        {
          "expression": "Apache-2.0",
          "acknowledgement": "declared"
        }
      ]
    },
    {
      "type": "library",
      "bom-ref": "comp-id",
      "name": "lib-id",
      "version": "2.0.0",
      "licenses": [
        {
          "license": {
            "id": "BSD-3-Clause",
            "acknowledgement": "declared"
          }
        }
      ]
    }
  ]
}
`)

// CDX: one component with acknowledgement=concluded (should NOT count as declared)
var cdx21CompWithConcludedOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-concluded-only-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-concluded",
      "name": "lib-concluded",
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

// SPDX 3.0: one component with hasDeclaredLicense relationship (Apache-2.0) — score 10.0
var spdx3CompWithDeclaredLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package", "SPDXRef-License-Apache"],
      "profileConformance": ["core", "software", "licensing"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-with-declared-license",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-Apache",
      "name": "Apache-2.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-License-Apache"],
      "relationshipType": "hasDeclaredLicense"
    }
  ]
}
`)

// SPDX 3.0: two components with hasDeclaredLicense — score 10.0
var spdx3TwoCompsWithDeclaredLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2", "SPDXRef-License-Apache", "SPDXRef-License-BSD"],
      "profileConformance": ["core", "software", "licensing"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "lib-with-apache",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "lib-with-bsd",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-Apache",
      "name": "Apache-2.0"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-BSD",
      "name": "BSD-3-Clause"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-License-Apache"],
      "relationshipType": "hasDeclaredLicense"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package2",
      "to": ["SPDXRef-License-BSD"],
      "relationshipType": "hasDeclaredLicense"
    }
  ]
}
`)

// SPDX 3.0: two components — only one has hasDeclaredLicense — partial score
var spdx3TwoCompsOneWithDeclaredLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2", "SPDXRef-License-Apache"],
      "profileConformance": ["core", "software", "licensing"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "lib-with-apache",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "lib-without-declared",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "License",
      "spdxId": "SPDXRef-License-Apache",
      "name": "Apache-2.0"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-License-Apache"],
      "relationshipType": "hasDeclaredLicense"
    }
  ]
}
`)

// SPDX 3.0: one component without hasDeclaredLicense — score 0
var spdx3CompWithoutDeclaredLicense = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "BSI v2.1 Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "lib-without-declared-license",
      "software_packageVersion": "1.0.0"
    }
  ]
}
`)

func TestBSIV21CompOriginalLicences(t *testing.T) {
	ctx := context.Background()

	// license expression with acknowledgement=declared → score 10.0
	t.Run("expressionDeclared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithExpressionDeclared, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "original licence (declared) declared for all components", got.Desc)
	})

	// license ID with acknowledgement=declared → score 10.0
	t.Run("licenseIDDeclared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithLicenseIDDeclared, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "original licence (declared) declared for all components", got.Desc)
	})

	// one comp with expression declared, one with ID declared → both pass → score 10.0
	t.Run("bothExpressionAndIDDeclared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsExpressionAndIDDeclared, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "original licence (declared) declared for all components", got.Desc)
	})

	// acknowledgement=concluded only (no declared) → score 0.0
	t.Run("concludedOnlyNoDeclared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithConcludedOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare original licence (declared)", got.Desc)
	})

	// 1 of 2 components has declared license → partial score 5.0
	t.Run("partialDeclared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21TwoCompsConcludedAndDeclared, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare original licence (declared)", got.Desc)
	})

	// license without acknowledgement (CDX 1.6+ defaults to declared) → score 10.0
	t.Run("licenseNoAcknowledgementDefaultsToDeclared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithLicenseNoAcknowledgement, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "original licence (declared) declared for all components", got.Desc)
	})

	// custom license ref (not a valid SPDX ID) → score 0.0
	t.Run("customLicenseRefInvalid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithCustomLicenseRef, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare original licence (declared)", got.Desc)
	})

	// no components → score 0.0
	t.Run("noComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, []byte(`{"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:test", "version": 1, "components": []}`), sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components found", got.Desc)
	})

	// SPDX 3.0: hasDeclaredLicense relationship (Apache-2.0) → score 10.0
	t.Run("spdx3DeclaredLicenseApache", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "original licence (declared) declared for all components", got.Desc)
	})

	// SPDX 3.0: two components with hasDeclaredLicense → score 10.0
	t.Run("spdx3BothDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsWithDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "original licence (declared) declared for all components", got.Desc)
	})

	// SPDX 3.0: 1 of 2 components has hasDeclaredLicense → partial score 5.0
	t.Run("spdx3PartialDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsOneWithDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare original licence (declared)", got.Desc)
	})

	// SPDX 3.0: no hasDeclaredLicense → score 0.0
	t.Run("spdx3NoDeclaredLicense", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithoutDeclaredLicense, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompOriginalLicences(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare original licence (declared)", got.Desc)
	})
}

// SPDX 3.0 - Component with distribution artifact filename
var spdx3CompWithFilename = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "TestPackage",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File",
      "name": "test-package-1.0.0.jar",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-File"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Component without distribution artifact relationship
var spdx3CompWithMissingFilename = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "TestPackage",
      "software_packageVersion": "1.0.0"
    }
  ]
}
`)

func TestBSIV21CompFilename(t *testing.T) {
	ctx := context.Background()

	// SPDX 3.0: hasDistributionArtifact relationship to software_File
	t.Run("spdx3CompWithFilename", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompFilename(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "filename declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: no hasDistributionArtifact relationship
	t.Run("spdx3CompWithMissingFilename", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithMissingFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompFilename(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare filename", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// SPDX 3.0 - Component with distribution artifact file containing SHA-512 hash
var spdx3CompWithDeployableHash = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "TestPackage",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File",
      "name": "test-package-1.0.0.jar",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-File"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Two components, both with distribution artifact + SHA-512 hash
var spdx3TwoCompsWithDeployableHash = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "PackageOne",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "PackageTwo",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File1",
      "name": "package1-1.0.0.jar",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File2",
      "name": "package2-2.0.0.jar",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-File1"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package2",
      "to": ["SPDXRef-File2"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Two components, one with deployable hash, one without
var spdx3TwoCompsOneWithDeployableHash = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "PackageOne",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "PackageTwo",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File1",
      "name": "package1-1.0.0.jar",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-File1"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Component with distribution artifact file but only MD5 hash (not acceptable)
var spdx3CompWithDeployableHashMD5Only = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "TestPackage",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File",
      "name": "test-package-1.0.0.jar",
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "md5",
          "hashValue": "d41d8cd98f00b204e9800998ecf8427e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-File"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// ===========================================================================
// TestBSIV21CompDeployableHash
// ===========================================================================

func TestBSIV21CompDeployableHash(t *testing.T) {
	ctx := context.Background()

	// SPDX 3.0: distribution artifact file with SHA-512 hash → score 10.0
	t.Run("spdx3CompWithDeployableHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithDeployableHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDeployableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "deployable component hash declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: two components both with distribution artifact + SHA-512 → score 10.0
	t.Run("spdx3TwoCompsWithDeployableHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsWithDeployableHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDeployableHash(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "deployable component hash declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: 1 of 2 components has deployable hash → partial score 5.0
	t.Run("spdx3PartialDeployableHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsOneWithDeployableHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDeployableHash(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare deployable component hash", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: no distribution artifact file → score 0.0
	t.Run("spdx3NoDeployableHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithMissingFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare deployable component hash", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: distribution artifact with MD5 only → score 0.0
	t.Run("spdx3DeployableHashMD5Only", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithDeployableHashMD5Only, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompDeployableHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare deployable component hash", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// SPDX 3.0 - Component with distribution artifact file having executable purpose
var spdx3CompWithExecutableProp = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package", "SPDXRef-File"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "TestPackage",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File",
      "name": "test-package-1.0.0.jar",
      "software_additionalPurpose": ["executable"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-Package"],
      "relationshipType": "describes",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-File"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Component with distribution artifact file having archive purpose
var spdx3CompWithArchivePropOnly = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package", "SPDXRef-File"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "TestPackage",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File",
      "name": "test-package-1.0.0.jar",
      "software_additionalPurpose": ["archive"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-Package"],
      "relationshipType": "describes",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-File"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Component with distribution artifact file having structured (container) purpose
var spdx3CompWithStructuredProp = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package", "SPDXRef-File"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package",
      "name": "TestPackage",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File",
      "name": "test-package-1.0.0.tar.gz",
      "software_additionalPurpose": ["container"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-Package"],
      "relationshipType": "describes",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package",
      "to": ["SPDXRef-File"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Two components, one with container (structured) purpose, one with archive purpose
var spdx3TwoCompsOneStructured = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2", "SPDXRef-File1", "SPDXRef-File2"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "PackageOne",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "PackageTwo",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File1",
      "name": "package1-1.0.0.tar.gz",
      "software_additionalPurpose": ["container"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File2",
      "name": "package2-2.0.0.jar",
      "software_additionalPurpose": ["archive"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-Package1"],
      "relationshipType": "describes",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-Package2"],
      "relationshipType": "dependsOn",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-File1"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package2",
      "to": ["SPDXRef-File2"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// SPDX 3.0 - Two components, one with executable purpose, one with archive purpose
var spdx3TwoCompsOneExecutable = []byte(`
{
  "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
  "@graph": [
    {
      "type": "SpdxDocument",
      "spdxId": "SPDXRef-DOCUMENT",
      "name": "Test",
      "creationInfo": "_:creationinfo",
      "element": ["SPDXRef-Package1", "SPDXRef-Package2", "SPDXRef-File1", "SPDXRef-File2"],
      "profileConformance": ["core", "software"]
    },
    {
      "type": "CreationInfo",
      "@id": "_:creationinfo",
      "specVersion": "3.0.1",
      "created": "2024-01-15T10:30:00Z",
      "createdBy": ["_:author"]
    },
    {
      "type": "Person",
      "@id": "_:author",
      "name": "Test Author"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package1",
      "name": "PackageOne",
      "software_packageVersion": "1.0.0"
    },
    {
      "type": "software_Package",
      "spdxId": "SPDXRef-Package2",
      "name": "PackageTwo",
      "software_packageVersion": "2.0.0"
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File1",
      "name": "package1-1.0.0.jar",
      "software_additionalPurpose": ["executable"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "software_File",
      "spdxId": "SPDXRef-File2",
      "name": "package2-2.0.0.jar",
      "software_additionalPurpose": ["archive"],
      "verifiedUsing": [
        {
          "type": "Hash",
          "algorithm": "sha512",
          "hashValue": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        }
      ]
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-DOCUMENT",
      "to": ["SPDXRef-Package1"],
      "relationshipType": "describes",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-Package2"],
      "relationshipType": "dependsOn",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package1",
      "to": ["SPDXRef-File1"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    },
    {
      "type": "Relationship",
      "from": "SPDXRef-Package2",
      "to": ["SPDXRef-File2"],
      "relationshipType": "hasDistributionArtifact",
      "completeness": "complete"
    }
  ]
}
`)

// ===========================================================================
// TestBSIV21CompExecutableProperty
// ===========================================================================

func TestBSIV21CompExecutableProperty(t *testing.T) {
	ctx := context.Background()

	// SPDX 3.0: distribution artifact file with executable purpose → score 10.0
	t.Run("spdx3CompWithExecutableProp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithExecutableProp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompExecutableProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "executable property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: distribution artifact file with archive purpose (not executable) → score 0.0
	t.Run("spdx3CompWithArchivePropOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithArchivePropOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompExecutableProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare executable property", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: 1 of 2 components has executable purpose → partial score 5.0
	t.Run("spdx3PartialExecutableProp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsOneExecutable, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompExecutableProperty(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare executable property", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: no distribution artifact file → score 0.0
	t.Run("spdx3NoDistributionArtifact", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithMissingFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompExecutableProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare executable property", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV21CompArchiveProperty
// ===========================================================================

func TestBSIV21CompArchiveProperty(t *testing.T) {
	ctx := context.Background()

	// SPDX 3.0: distribution artifact file with archive purpose → score 10.0
	t.Run("spdx3CompWithArchiveProp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithArchivePropOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompArchiveProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "archive property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: distribution artifact file with executable purpose (not archive) → score 0.0
	t.Run("spdx3CompWithExecutablePropOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithExecutableProp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompArchiveProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare archive property", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: 1 of 2 components has archive purpose → partial score 5.0
	t.Run("spdx3PartialArchiveProp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsOneExecutable, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompArchiveProperty(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare archive property", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: no distribution artifact file → score 0.0
	t.Run("spdx3NoDistributionArtifact", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithMissingFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompArchiveProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare archive property", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ===========================================================================
// TestBSIV21CompStructuredProperty
// ===========================================================================

func TestBSIV21CompStructuredProperty(t *testing.T) {
	ctx := context.Background()

	// SPDX 3.0: distribution artifact file with container (structured) purpose → score 10.0
	t.Run("spdx3CompWithStructuredProp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithStructuredProp, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompStructuredProperty(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "structured property declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: distribution artifact file with archive purpose (not structured) → score 0.0
	t.Run("spdx3CompWithArchivePropOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithArchivePropOnly, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompStructuredProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare structured property", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: 1 of 2 components has structured purpose → partial score 5.0
	t.Run("spdx3PartialStructuredProp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3TwoCompsOneStructured, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompStructuredProperty(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1/2 components declare structured property", got.Desc)
		assert.False(t, got.Ignore)
	})

	// SPDX 3.0: no distribution artifact file → score 0.0
	t.Run("spdx3NoDistributionArtifact", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdx3CompWithMissingFilename, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompStructuredProperty(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare structured property", got.Desc)
		assert.False(t, got.Ignore)
	})
}

//
// TestBSIV21CompEffectiveLicence
//

// CDX: component carrying the taxonomy spelling, bsi:component:effectiveLicence.
var cdx21CompEffectiveLicenceBritish = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-eff-lic-001",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-eff-lic-british",
      "name": "lib-effective-licence",
      "version": "1.0.0",
      "properties": [
        {
          "name": "bsi:component:effectiveLicence",
          "value": "Apache-2.0"
        }
      ]
    }
  ]
}
`)

// CDX: component carrying the TR-03183-2 spelling, bsi:component:effectiveLicense.
var cdx21CompEffectiveLicenseAmerican = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-eff-lic-002",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-eff-lic-american",
      "name": "lib-effective-license",
      "version": "1.0.0",
      "properties": [
        {
          "name": "bsi:component:effectiveLicense",
          "value": "MIT"
        }
      ]
    }
  ]
}
`)

// CDX: component without any effective licence property.
var cdx21CompWithoutEffectiveLicence = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:bsiv21-cdx-eff-lic-003",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "comp-no-eff-lic",
      "name": "lib-without-effective-licence",
      "version": "1.0.0"
    }
  ]
}
`)

func TestBSIV21CompEffectiveLicence(t *testing.T) {
	ctx := context.Background()

	// taxonomy spelling (effectiveLicence) -> score 10.0
	t.Run("taxonomySpelling", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompEffectiveLicenceBritish, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompEffectiveLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "effective licence declared for all components", got.Desc)
	})

	// TR-03183-2 spelling (effectiveLicense) -> score 10.0
	t.Run("technicalGuidelineSpelling", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompEffectiveLicenseAmerican, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompEffectiveLicence(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "effective licence declared for all components", got.Desc)
	})

	// property missing entirely -> score 0.0
	t.Run("missing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithoutEffectiveLicence, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompEffectiveLicence(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare effective licence", got.Desc)
	})
}
