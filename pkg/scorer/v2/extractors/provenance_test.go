// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

var cdxSBOMTimestampValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2020-04-13T20:20:39+00:00"
  },
  "components": []
}
`)

var spdxSBOMTimestampValid = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2020-04-13T20:20:39Z"
  },
  "packages": []
}
`)

var cdxSBOMTimestampFormatInvalid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": "2020-04-13"
  },
  "components": []
}
`)

var spdxSBOMTimestampFormatInvalid = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2020-04-13"
  },
  "packages": []
}
`)

var cdxSBOMTimestampAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
  },
  "components": []
}
`)

var spdxSBOMTimestampAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
  },
  "packages": []
}
`)

var cdxSBOMTimestampEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": ""
  },
  "components": []
}
`)

var spdxSBOMTimestampEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": ""
  },
  "packages": []
}
`)

var cdxSBOMTimestampWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "timestamp": {"2020-04-13T20:20:39+00:00"}
  },
  "components": []
}
`)

var spdxSBOMTimestampWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": { "2020-04-13T20:20:39Z" }
  },
  "packages": []
}
`)

func TestSBOMTimestamp(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMTimestampValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMTimestampValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMTimestampValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTimestampValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMTimestampFormatInvalid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMTimestampFormatInvalid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "fix timestamp format", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMTimestampFormatInvalid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTimestampFormatInvalid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "fix timestamp format", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMTimestampAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMTimestampAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add timestamp", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMTimestampAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTimestampAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add timestamp", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMTimestampEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMTimestampEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add timestamp", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMTimestampEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTimestampEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTimestamp(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add timestamp", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMTimestampWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMTimestampWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMTimestampWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMTimestampWrongType, sbom.Signature{})
		require.Error(t, err)
	})

}

var cdxSBOMAuthorsValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
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

var spdxSBOMAuthorsValid = []byte(`
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

var cdxSBOMAuthorsAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {},
  "components": []
}
`)

var spdxSBOMAuthorsAbsent = []byte(`
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

var cdxSBOMAuthorsWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
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

var cdxSBOMAuthorsWithNameOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "authors": [
      {
        "name": "Samantha Wright"
      }
    ]
  }
}
`)

var spdxSBOMAuthorsWithNameOnly = []byte(`
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

var cdxSBOMAuthorsWithEmailOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "authors": [
      {
        "email": "samantha.wright@example.com"
      }
    ]
  },
  "components": []
}
`)

var spdxSBOMAuthorsWithEmailOnly = []byte(`
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

var cdxSBOMAuthorsMixed = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "authors": [
      {
        "name": "Samantha Wright",
        "email": "samantha.wright@example.com"
      },
      {
        "name": "",
        "email": ""
      }
    ]
  }
}
`)

func TestSBOMAuthor(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMAuthorsValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add author", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add author", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add author", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsEmptyString", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsEmptyString, sbom.Signature{})
		require.Error(t, err)

		// got := SBOMAuthors(doc)

		// assert.InDelta(t, 0.0, got.Score, 1e-9)
		// assert.Equal(t, "add author", got.Desc)
		// assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add author", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add author", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWrongType, sbom.Signature{})
		require.Error(t, err)

		// got := SBOMAuthors(doc)

		// assert.InDelta(t, 0.0, got.Score, 1e-9)
		// assert.Equal(t, "add author", got.Desc)
		// assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWrongType, sbom.Signature{})
		require.Error(t, err)

		// got := SBOMAuthors(doc)

		// assert.InDelta(t, 0.0, got.Score, 1e-9)
		// assert.Equal(t, "add author", got.Desc)
		// assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsMixed", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsMixed, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	// cdxSBOMAuthorsPartial
	t.Run("cdxSBOMAuthorsWithNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsWithNameOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithNameOnly, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMAuthorsWithEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMAuthorsWithEmailOnly", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmailOnly, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMAuthors(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxSBOMToolValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "name": "Awesome Tool",
          "version": "9.1.2"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolValid = []byte(`
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
  "creationInfo": {
  },
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

var cdxSBOMToolEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "name": "",
          "version": ""
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolEmptyString = []byte(`
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

var cdxSBOMToolWithEmptyName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "name": "",
          "version": "9.1.2"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithEmptyName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: -9.1.2"
    ]
  },
  "packages": []
}
`)

var cdxSBOMToolWithEmptyVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "name": "Awesome Tool",
          "version": ""
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolWithEmptyVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "creators": [
      "Tool: Awesome Tool-"
    ]
  },
  "packages": []
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

var cdxSBOMToolComponentsWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "tools": {
      "components": {}
    }
  },
  "components": []
}
`)

func TestSBOMCreationTool(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMToolValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMToolValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMToolEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMToolEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMToolWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add name to 1 tools", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMToolWithEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add name to 1 tools", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMToolWithEmptyVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithEmptyVersion, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add version to 1 tools", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMToolWithEmptyVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithEmptyVersion, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add version to 1 tools", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMToolWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMCreationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add tool", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMToolWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMToolComponentsWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolComponentsWrongType, sbom.Signature{})
		require.Error(t, err)
	})

}

var cdxSBOMSupplierValid = []byte(`
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

var cdxSBOMSupplierEmptyNameString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "name": "",
      "url": [
        "https://example.com"
      ]
    }
  },
  "components": []
}
`)

var cdxSBOMSupplierOnlyName = []byte(`
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

var cdxSBOMSupplierOnlyURL = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "supplier": {
      "url": ["https://example.com"]
    }
  }
}
`)

var cdxSBOMSupplierWhitespaceName = []byte(`
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

var cdxSBOMSupplierWrongType = []byte(`
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

var spdxSBOMGeneral = []byte(`
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

func TestSBOMSupplier(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMSupplierValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add supplier", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add supplier", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierEmptyNameString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierEmptyNameString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierOnlyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierOnlyName, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierOnlyURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierOnlyURL, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierWhitespaceName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWhitespaceName, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add supplier", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSupplierWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMGeneral", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMGeneral, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (SPDX)", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxSBOMSerialValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxSBOMNamespaceValid = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "documentNamespace": "https://example.com/minimal",
  "packages": []
}
`)

var cdxSBOMSerialEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "",
  "metadata": {},
  "components": []
}
`)

var spdxSBOMNamespaceEmptyString = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "documentNamespace": ""
}
`)

var cdxSBOMSerialInvalid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "kk89829shumskksjxnxjsksk",
  "metadata": {},
  "components": []
}
`)

var spdxSBOMNamespaceInvalid = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "documentNamespace": "not-a-uri"
}
`)

var cdxSBOMSerialMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {},
  "components": []
}
`)

var spdxSBOMNamespaceMissing = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "SPDXID": "SPDXRef-DOCUMENT"
}
`)

var cdxSBOMSerialWhitespace = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "   "
}
`)

var cdxSBOMSerialWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": {}
}
`)

var spdxSBOMNamespaceWrongType = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Tool: minimal-generator"]
  },
  "documentNamespace": {}
}
`)

func TestSBOMNamespace(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMSerialValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSerialValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMNamespaceValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMNamespaceValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSerialEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSerialEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add namespace", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMNamespaceEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMNamespaceEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add namespace", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSerialInvalid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSerialInvalid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add namespace", got.Desc)
		assert.False(t, got.Ignore)
	})

	// EXCEPTION: how can invalid NAMESPACE parsed ?
	// t.Run("spdxSBOMNamespaceInvalid", func(t *testing.T) {
	// 	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMNamespaceInvalid, sbom.Signature{})
	// 	require.NoError(t, err)

	// 	got := SBOMNamespace(doc)

	// 	assert.InDelta(t, 0.0, got.Score, 1e-9)
	// 	assert.Equal(t, "add namespace", got.Desc)
	// 	assert.False(t, got.Ignore)
	// })

	t.Run("cdxSBOMSerialMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSerialMissing, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add namespace", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMNamespaceMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMNamespaceMissing, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add namespace", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSerialWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSerialWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMNamespace(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add namespace", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMSerialWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSerialWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMNamespaceWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMNamespaceWrongType, sbom.Signature{})
		require.Error(t, err)
	})

}

var cdxSBOMLifeCycleValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      {
        "phase": "build"
      },
      {
        "phase": "post-build"
      },
      {
        "name": "platform-integration-testing",
        "description": "Integration testing specific to the runtime platform"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMLifeCycleTypePostBuildPhase = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      {
        "phase": "post-build"
      },
      {
        "name": "platform-integration-testing",
        "description": "Integration testing specific to the runtime platform"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMLifeCycleTypePITPhase = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      {
        "name": "platform-integration-testing",
        "description": "Integration testing specific to the runtime platform"
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMLifeCycleUnknownPhase = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "lifecycles": [
      {
        "phase": "alien-build-phase"
      }
    ]
  }
}
`)

var cdxSBOMLifeCycleAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMLifeCycleMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": []
  },
  "components": []
}
`)

var cdxSBOMLifeCycleEmptyString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      {
        "phase": ""
      }
    ]
  },
  "components": []
}
`)
var cdxSBOMLifeCycleWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": {}
  },
  "components": []
}
`)

var cdxSBOMLifeCycleWrongPhaseType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [
      {
        "phase": {}
      }
    ]
  },
  "components": []
}
`)

var cdxSBOMLifeCycleWhitespacePhase = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "lifecycles": [
      {
        "phase": "   "
      }
    ]
  }
}
`)

var cdxSBOMLifeCycleMixed = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "lifecycles": [
      { "phase": "build" },
      { "phase": "" }
    ]
  }
}
`)

func TestSBOMLifeCycle(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMLifeCycleValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleTypePostBuildPhase", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleTypePostBuildPhase, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleTypePITPhase", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleTypePITPhase, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add valid lifecycle", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleUnknownPhase", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleUnknownPhase, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add valid lifecycle", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add lifecycle", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleMissing, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add lifecycle", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add valid lifecycle", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMLifeCycleWrongPhaseType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleWrongPhaseType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMLifeCycleWhitespacePhase", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleWhitespacePhase, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add valid lifecycle", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMLifeCycleMixed", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMLifeCycleMixed, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMLifeCycle(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}
