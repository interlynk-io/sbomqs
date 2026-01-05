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
          "alg": "SHA-384",
          "content": "d4835048a0f57c74b8fb617d5366ab81376fc92bebe9a93bf24ba7f9da6c9aeeb6179f5d1361f6533211b15f3224cbad"
        },
        {
          "alg": "SHA-512",
          "content": "74a51ff45e4c11df9ba1f0094282c80489649cb157a75fa337992d2d4592a5a1b8cb4525de8db0ae25233553924d76c36e093ea7fa9df4e5b8b07fd2e074efd6"
        },
        {
          "alg": "SHA3-256",
          "content": "7478c7cf41c883a04ee89f1813f687886d53fa86f791fff90690c6221e3853aa"
        },
        {
          "alg": "SHA3-384",
          "content": "a1eea7229716487ad2ebe96b2f997a8408f32f14047994fbcc99b49012cf86c96dbd518e5d57a61b0e57dd37dd0b48f5"
        },
        {
          "alg": "SHA3-512",
          "content": "7d584825bc1767dfabe7e82b45ccb7a1119b145fa17e76b885e71429c706cef0a3171bc6575b968eec5da56a7966c02fec5402fcee55097ac01d40c550de9d20"
        },
        {
          "alg": "BLAKE2b-256",
          "content": "d8779633380c050bccf4e733b763ab2abd8ad2db60b517d47fd29bbf76433237"
        },
        {
          "alg": "BLAKE2b-384",
          "content": "e728ba56c2da995a559a178116c594e8bee4894a79ceb4399d8f479e5563cb1942b85936f646d14170717c576b14db7a"
        },
        {
          "alg": "BLAKE2b-512",
          "content": "f8ce8d612a6c85c96cf7cebc230f6ddef26e6cedcfbc4a41c766033cc08c6ba097d1470948226807fb2d88d2a2b6fc0ff5e5440e93a603086fdd568bafcd1a9d"
        },
        {
          "alg": "BLAKE3",
          "content": "26cdc7fb3fd65fc3b621a4ef70bc7d2489d5c19e70c76cf7ec20e538df0047cf"
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
          "algorithm": "SHA384",
          "checksumValue": "d4835048a0f57c74b8fb617d5366ab81376fc92bebe9a93bf24ba7f9da6c9aeeb6179f5d1361f6533211b15f3224cbad"
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

var cdxCompWithOnlyWeakValidChecksums = []byte(`
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

var spdxCompWithOnlyWeakValidChecksums = []byte(`
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

var cdxCompWithOnlyStrongValidChecksums = []byte(`
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
          "alg": "SHA-384",
          "content": "d4835048a0f57c74b8fb617d5366ab81376fc92bebe9a93bf24ba7f9da6c9aeeb6179f5d1361f6533211b15f3224cbad"
        },
        {
          "alg": "SHA-512",
          "content": "74a51ff45e4c11df9ba1f0094282c80489649cb157a75fa337992d2d4592a5a1b8cb4525de8db0ae25233553924d76c36e093ea7fa9df4e5b8b07fd2e074efd6"
        },
        {
          "alg": "SHA3-256",
          "content": "7478c7cf41c883a04ee89f1813f687886d53fa86f791fff90690c6221e3853aa"
        },
        {
          "alg": "SHA3-384",
          "content": "a1eea7229716487ad2ebe96b2f997a8408f32f14047994fbcc99b49012cf86c96dbd518e5d57a61b0e57dd37dd0b48f5"
        },
        {
          "alg": "SHA3-512",
          "content": "7d584825bc1767dfabe7e82b45ccb7a1119b145fa17e76b885e71429c706cef0a3171bc6575b968eec5da56a7966c02fec5402fcee55097ac01d40c550de9d20"
        },
        {
          "alg": "BLAKE2b-256",
          "content": "d8779633380c050bccf4e733b763ab2abd8ad2db60b517d47fd29bbf76433237"
        },
        {
          "alg": "BLAKE2b-384",
          "content": "e728ba56c2da995a559a178116c594e8bee4894a79ceb4399d8f479e5563cb1942b85936f646d14170717c576b14db7a"
        },
        {
          "alg": "BLAKE2b-512",
          "content": "f8ce8d612a6c85c96cf7cebc230f6ddef26e6cedcfbc4a41c766033cc08c6ba097d1470948226807fb2d88d2a2b6fc0ff5e5440e93a603086fdd568bafcd1a9d"
        },
        {
          "alg": "BLAKE3",
          "content": "26cdc7fb3fd65fc3b621a4ef70bc7d2489d5c19e70c76cf7ec20e538df0047cf"
        }
      ]
    }
  ]
}
`)

var spdxCompWithOnlyStrongValidChecksums = []byte(`
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
          "algorithm": "SHA384",
          "checksumValue": "d4835048a0f57c74b8fb617d5366ab81376fc92bebe9a93bf24ba7f9da6c9aeeb6179f5d1361f6533211b15f3224cbad"
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

func TestCompWithWeakChecksums1(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithWeakChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithWeakChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithOnlyWeakValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithOnlyWeakValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithWeakChecksums(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "upgrade 1 component to SHA-256+", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithOnlyWeakValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithOnlyWeakValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithWeakChecksums(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "upgrade 1 component to SHA-256+", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithOnlyStrongValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithOnlyStrongValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithWeakChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithOnlyStrongValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithOnlyStrongValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithWeakChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithStrongChecksums1(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithStrongChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithMixValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithMixValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithStrongChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithOnlyWeakValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithOnlyWeakValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithStrongChecksums(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithOnlyWeakValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithOnlyWeakValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithStrongChecksums(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithOnlyStrongValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithOnlyStrongValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithStrongChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithOnlyStrongValidChecksums", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithOnlyStrongValidChecksums, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithStrongChecksums(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}
