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

var cdxSBOMValidSpec = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMValidSpec = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMUnknownSpec = []byte(`
{
  "bomFormat": "UnknownSpec",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMUnknownSpec = []byte(`
{
  "spdxVersion": "SPDX-9.9",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMEmptySpec = []byte(`
{
  "bomFormat": "",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMEmptySpec = []byte(`
{
  "spdxVersion": "",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMMissingSpec = []byte(`
{
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMMissingSpec = []byte(`
{
  "SPDXID": "SPDXRef-DOCUMENT".
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMWhitespaceSpec = []byte(`
{
  "bomFormat": "   ",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMWhitespaceSpec = []byte(`
{
  "spdxVersion": "   ",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMSpecWrongType = []byte(`
{
  "bomFormat": {},
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMSpecWrongType = []byte(`
{
  "spdxVersion": {},
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

func TestSBOMSpec(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMValidSpec", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMValidSpec, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithSpec(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "cyclonedx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMValidSpec", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMValidSpec, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithSpec(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "spdx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMUnknownSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMUnknownSpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMUnknownSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMUnknownSpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMEmptySpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMEmptySpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMEmptySpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMEmptySpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMMissingSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMissingSpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMMissingSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMissingSpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMWhitespaceSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWhitespaceSpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMWhitespaceSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWhitespaceSpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMSpecWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSpecWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMSpecWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMSpecWrongType, sbom.Signature{})
		require.Error(t, err)
	})
}

var cdxSBOMValidVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMValidVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMUnknownVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "4.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMUnknownVersion = []byte(`
{
  "spdxVersion": "SPDX-9.9",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMEmptyVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMEmptyVersion = []byte(`
{
  "spdxVersion": "",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMMissingVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMMissingVersion = []byte(`
{
  "SPDXID": "SPDXRef-DOCUMENT".
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMWhitespaceVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "  ",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMWhitespaceVersion = []byte(`
{
  "spdxVersion": "   ",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMVersionWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": {},
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMVersionWrongType = []byte(`
{
  "spdxVersion": {},
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

func TestSBOMSpecVersion(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMValidVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMValidVersion, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSpecVersion(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "v1.6", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMValidVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMValidVersion, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSpecVersion(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SPDX-2.3", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMUnknownVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMUnknownVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMUnknownVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMUnknownVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMEmptyVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMEmptyVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMEmptyVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMEmptyVersion, sbom.Signature{})
		require.Error(t, err)
	})

	// EXCEPTION
	t.Run("cdxSBOMMissingVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMMissingVersion, sbom.Signature{})
		require.NoError(t, err)

		// got := SBOMSpecVersion(doc)

		// assert.InDelta(t, 10.0, got.Score, 1e-9)
		// assert.Equal(t, "SPDX-2.3", got.Desc)
		// assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMMissingVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMMissingVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMWhitespaceVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWhitespaceVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMWhitespaceVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWhitespaceVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMVersionWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMVersionWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMVersionWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMVersionWrongType, sbom.Signature{})
		require.Error(t, err)
	})
}

var cdxSBOMValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMValid = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "packages": []
}
`)

var cdxSBOMValidYAML = []byte(`
  bomFormat: CycloneDX
  specVersion: "1.6"
  metadata: {}
`)

var spdxSBOMValidTagValue = []byte(`
SPDXVersion: SPDX-2.3
SPDXID: SPDXRef-DOCUMENT
`)

func TestSBOMFileFormat(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMFileFormat(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "json", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMFileFormat(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "json", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMValidYAML", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMValidYAML, sbom.Signature{})
		require.Error(t, err)

	})

	t.Run("spdxSBOMValidTagValue", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMValidTagValue, sbom.Signature{})
		require.Error(t, err)
	})

}
