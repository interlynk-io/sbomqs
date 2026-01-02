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

var spdxSBOMWithNoComponents = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  }
}
`)

var spdxSBOMWithComponentMissingName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-EmptyName",
      "name": "",
      "versionInfo": "1.4.0"
    }
  ]
}
`)

func TestCompWithName_SPDX(t *testing.T) {
	ctx := context.Background()

	t.Run("spdxSBOMWithComponentMissingName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithComponentMissingName, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithName(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMWithNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithNoComponents, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithName(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore, "no components → N/A")
		assert.Equal(t, got.Desc, "N/A (no components)")
	})
}

var spdxSBOMWithComponentNameVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "name": "A",
	  "SPDXID": "SPDXRef-A",
      "versionInfo": "1.0.0"
    }
  ]
}
`)

var spdxSBOMWithComponentsNameAndVersionMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
  	  "SPDXID": "SPDXRef-A",
      "name": "A",
      "versionInfo": ""
    }
  ]
}
`)

func TestCompWithVersion_SPDX(t *testing.T) {
	ctx := context.Background()

	t.Run("spdxSBOMWithComponentNameVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithComponentNameVersion, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithVersion(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMWithComponentsNameAndVersionMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithComponentsNameAndVersionMissing, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithVersion(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMWithNoComponents", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithNoComponents, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithVersion(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})
}

var spdxSBOMWithComponentNameVersionAndMissingID = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "",
      "name": "A",
      "versionInfo": "1.0.0"
    }
  ]
}
`)

func TestCompWithUniqLocalIDs_SPDX(t *testing.T) {
	t.Run("spdxSBOMWithComponentNameVersionAndID", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithComponentNameVersion, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithUniqLocalIDs(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMWithComponentNameVersionAndMissingID", func(t *testing.T) {
		ctx := context.Background()
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithComponentNameVersionAndMissingID, sbom.Signature{})

		// Since, SPDXID is empty,
		// therefore, it will return an "error":
		// "failed to parse SPDX identifier ''"}
		require.Error(t, err)
	})

	t.Run("spdxSBOMWithNoComponents", func(t *testing.T) {
		ctx := context.Background()
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithNoComponents, sbom.Signature{})
		require.NoError(t, err)

		out := CompWithUniqLocalIDs(doc)
		assert.InDelta(t, 0.0, out.Score, 0.0001)
		assert.Equal(t, "N/A (no components)", out.Desc)
		assert.True(t, out.Ignore)
	})
}

var cdxSBOMWithNoComponents = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [
      {
        "name": "syft",
        "version": "0.95.0"
      }
    ]
  }
}
`)

var cdxSBOMComponentWithMissingName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [{ "name": "syft", "version": "0.95.0" }]
  },
  "components": [
    {
      "type": "library",
      "name": "   ",
      "version": "0.1.0"
    }
  ]
}
`)

func TestCompWithName_CDX(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMComponentWithMissingName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMComponentWithMissingName, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithName(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMWithNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithNoComponents, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithName(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.True(t, got.Ignore)
		assert.Equal(t, "N/A (no components)", got.Desc)
	})
}

var cdxSBOMComponentWithNameVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [{ "name": "syft", "version": "0.95.0" }]
  },
  "components": [
    {
      "type": "library",
      "name": "A",
      "version": "1.0.0"
    }
  ]
}
`)

var cdxSBOMComponentWithNameAndMissingVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [{ "name": "syft", "version": "0.95.0" }]
  },
  "components": [
    {
      "type": "library",
      "name": "A",
      "version": ""
    }
  ]
}
`)

func TestCompWithVersion_CDX(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMComponentWithNameVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMComponentWithNameVersion, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithVersion(doc)
		assert.InDelta(t, 10.0, got.Score, 0.0001)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMComponentWithNameAndMissingVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMComponentWithNameAndMissingVersion, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithVersion(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMWithNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithNoComponents, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithVersion(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})
}

var cdxSBOMComponentWithNameVersionAndMissingID = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [{ "name": "syft", "version": "0.95.0" }]
  },
  "components": [
    {
      "type": "library",
      "name": "A",
      "version": "1.0.0"
    }
  ]
}
`)

func TestCompWithUniqLocalIDs_CDX(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMComponentWithNameVersionAndMissingID", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMComponentWithNameVersionAndMissingID, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithUniqLocalIDs(doc)
		assert.InDelta(t, 0.0, got.Score, 0.0001)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMWithNoComponents", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithNoComponents, sbom.Signature{})
		require.NoError(t, err)

		out := CompWithUniqLocalIDs(doc)
		assert.InDelta(t, 0.0, out.Score, 0.0001)
		assert.Equal(t, "N/A (no components)", out.Desc)
		assert.True(t, out.Ignore)
	})
}
