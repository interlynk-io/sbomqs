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
              "alg": "SHA-256",
              "content": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
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
              "alg": "SHA-256",
              "content": "b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a"
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
              "alg": "SHA-256",
              "content": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
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
              "alg": "SHA-256",
              "content": "c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2"
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
              "alg": "SHA-256",
              "content": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
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

	// source-distribution ext ref present but no hash → score 0.0
	t.Run("sourceDistributionNoHash", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx21CompWithSourceDistributionURLNoHash, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source code hash", got.Desc)
		assert.False(t, got.Ignore)
	})

	// no ext refs at all → score 0.0
	t.Run("noExtRefs", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithProperties, sbom.Signature{})
		require.NoError(t, err)

		got := BSIV21CompSourceHash(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare source code hash", got.Desc)
		assert.False(t, got.Ignore)
	})
}
