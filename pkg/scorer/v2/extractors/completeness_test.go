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

var cdxSBOMCompletenessDeclared = []byte(
	`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "compositions": [
    {
      "aggregate": "complete"
	}
  ]
}
`)

var cdxSBOMCompletenessDeclaredIncomplete = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "compositions": [
    {
      "aggregate": "incomplete"
	}
  ]
}
`)

var cdxSBOMCompletenessDeclaredUnknown = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1
}
`)

var cdxSBOMCompletenessDeclaredEmpty = []byte(
	`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "compositions": []
}
`)

var cdxSBOMCompletenessDeclaredMissingAggregate = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "compositions": [{}]
}
`)

var spdxSBOMExample = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": []
}
`)

func TestSBOMWithDeclaredCompleteness(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMCompletenessDeclared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMCompletenessDeclared, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithDeclaredCompleteness(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM completeness declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMCompletenessDeclaredIncomplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMCompletenessDeclaredIncomplete, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithDeclaredCompleteness(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM completeness not declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMCompletenessDeclaredUnknown", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMCompletenessDeclaredUnknown, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithDeclaredCompleteness(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM completeness not declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMCompletenessDeclaredEmpty", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMCompletenessDeclaredEmpty, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithDeclaredCompleteness(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM completeness not declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMCompletenessDeclaredMissingAggregate", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMCompletenessDeclaredMissingAggregate, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithDeclaredCompleteness(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "SBOM completeness not declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMExample", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMExample, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithDeclaredCompleteness(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (SPDX)", got.Desc)
		assert.False(t, got.Ignore)
	})
}

var cdxCompWithValidPackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0"
    },
    {
      "type": "library",
      "name": "library-a",
      "version": "1.0"
    },
    {
      "type": "framework",
      "name": "framework-a",
      "version": "1.0"
    },
    {
      "type": "container",
      "name": "container-a",
      "version": "1.0"
    },
    {
      "type": "operating-system",
      "name": "operating-system-a",
      "version": "1.0"
    },
    {
      "type": "firmware",
      "name": "firmware-a",
      "version": "1.0"
    },
    {
      "type": "device",
      "name": "device-a",
      "version": "1.0"
    },
    {
      "type": "file",
      "name": "file-a",
      "version": "1.0"
    }
  ]
}
`)

var spdxCompWithValidPackagePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "APPLICATION"
    },
    {
      "SPDXID": "SPDXRef-Lib",
      "name": "library-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "LIBRARY"
    },
    {
      "SPDXID": "SPDXRef-Framework",
      "name": "framework-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "FRAMEWORK"
    },
    {
      "SPDXID": "SPDXRef-Container",
      "name": "container-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "CONTAINER"
    },
    {
      "SPDXID": "SPDXRef-OS",
      "name": "os-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "OPERATING-SYSTEM"
    },
    {
      "SPDXID": "SPDXRef-Firmware",
      "name": "firmware-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "FIRMWARE"
    },
    {
      "SPDXID": "SPDXRef-Device",
      "name": "device-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "DEVICE"
    },
    {
      "SPDXID": "SPDXRef-File",
      "name": "file-a",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "FILE"
    }
  ]
}
`)

var cdxCompWithInValidPackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "foo",
      "name": "foo-a",
      "version": "1.0"
    },
    {
      "type": "bar",
      "name": "bar-a",
      "version": "1.0"
    }   
  ]
}
`)

var spdxCompWithInvalidPackagePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Foo",
      "name": "foo",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "FOO"
    }
  ]
}
`)

var cdxCompWithTwoInValidAndOneMissingPackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "foo",
      "name": "foo-a",
      "version": "1.0"
    },
    {
      "type": "bar",
      "name": "bar-a",
      "version": "1.0"
    },
	{
      "name": "red-a",
      "version": "1.0"
    }   
  ]
}
`)

var spdxCompWithOneInvalidAndOneMissingPackagePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-EmptyPurpose",
      "name": "acme",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "FOO"
    },
	{
      "SPDXID": "SPDXRef-EmptyPurpose",
      "name": "foo",
      "versionInfo": "1.1",
      "primaryPackagePurpose": ""
    }
  ]
}
`)

var cdxCompWithAbsentPackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "name": "acme",
      "version": "0.1.0"
    }
  ]
}
`)

var spdxCompWithAbsentPackagePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-NoPurpose",
      "name": "acme",
      "versionInfo": "1.0"
    }
  ]
}
`)

var cdxTwoCompWithAbsentPackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "name": "acme",
      "version": "0.1.0"
    },
	{
      "name": "phips",
      "version": "0.1.1"
    }
  ]
}
`)

var cdxCompWithOneAbsentPackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "name": "acme",
      "version": "0.1.0"
    },
	{
	  "type": "application",
	  "name": "phips",
      "version": "0.1.1"
    }
  ]
}
`)

var cdxCompWithEmptyStringPackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "",
      "name": "acme",
      "version": "0.1.0"
    }
  ]
}
`)

var spdxCompWithEmptyPackagePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-EmptyPurpose",
      "name": "acme",
      "versionInfo": "1.0",
      "primaryPackagePurpose": ""
    }
  ]
}
`)

var cdxCompWithWhitespacePackageType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "   ",
      "name": "acme",
      "version": "0.1.0"
    }
  ]
}
`)

var spdxCompWithWhitspacePackagePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-WrongType",
      "name": "acme",
      "versionInfo": "1.0",
      "primaryPackagePurpose": "    "
    }
  ]
}
`)

var cdxCompWithWrongPackageSchemaType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": {},
      "name": "acme",
      "version": "0.1.0"
    }
  ]
}
`)

var spdxCompWithWrongTypePackagePurpose = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-WrongType",
      "name": "acme",
      "versionInfo": "1.0",
      "primaryPackagePurpose": {}
    }
  ]
}
`)

func TestCompWithPackagePurpose(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompWithValidPackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithValidPackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithValidPackagePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithValidPackagePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithInValidPackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithInValidPackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "correct for 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithInvalidPackagePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithInvalidPackagePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "correct for 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithTwoInValidAndOneMissingPackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithTwoInValidAndOneMissingPackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "correct for 2 components (others missing)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithOneInvalidAndOneMissingPackagePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithOneInvalidAndOneMissingPackagePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "correct for 1 component (others missing)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithAbsentPackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithAbsentPackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithAbsentPackagePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithAbsentPackagePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoCompWithAbsentPackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoCompWithAbsentPackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithOneAbsentPackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithOneAbsentPackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithEmptyStringPackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithEmptyStringPackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithEmptyPackagePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithEmptyPackagePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithWhitespacePackageType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithWhitespacePackageType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompWithWhitspacePackagePurpose", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithWhitspacePackagePurpose, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompWithWrongPackageSchemaType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithWrongPackageSchemaType, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxCompWithWrongTypePackagePurpose", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithWrongTypePackagePurpose, sbom.Signature{})
		require.Error(t, err)
	})
}

// "https://github.com/demo/foo"
var cdxCompValidSourceCode = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": "https://github.com/acme/application-a"
        }
      ]
    }
  ]
}
`)

var spdxCompHaveNoDeterminsticFieldForSourceCode = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "application-a",
      "versionInfo": "1.0",
      "downloadLocation": "https://github.com/acme/application-a"
    }
  ]
}
`)

var cdxCompSourceCodeAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0"
    }
  ]
}
`)

var cdxCompSourceCodeMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        {
	  	}
      ]
    }
  ]
}
`)

var cdxCompSourceCodeEmptyURLString = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        {
          "type": "vcs",
          "url": ""
        }
      ]
    }
  ]
}
`)

var cdxCompSourceCodeURLMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        {
          "type": "vcs"
        }
      ]
    }
  ]
}
`)

var cdxCompSourceCodeTypeMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        {
          "url": "https://github.com/acme/application-a"
        }
      ]
    }
  ]
}
`)

var cdxCompSourceCodeValidWebsiteType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        {
          "type": "website",
          "url": "https://github.com/acme/application-a"
        }
      ]
    }
  ]
}
`)

var cdxCompSourceCodeInValidType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        {
          "type": "foo-bar",
          "url": "https://github.com/acme/application-a"
        }
      ]
    }
  ]
}
`)

var cdxCompSourceCodeEmptyArray = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": []
    }
  ]
}
`)

var cdxCompSourceCodeMixedRefs = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": [
        { "type": "website", "url": "https://example.com" },
        { "type": "vcs", "url": "https://github.com/acme/application-a" }
      ]
    }
  ]
}
`)

var cdxCompSourceCodeWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "application-a",
      "version": "1.0",
      "externalReferences": {}
    }
  ]
}
`)

func TestCompWithSourceCode(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxCompValidSourceCode", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompValidSourceCode, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxCompHaveNoDeterminsticFieldForSourceCode", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompHaveNoDeterminsticFieldForSourceCode, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeMissing, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeEmptyURLString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeEmptyURLString, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeURLMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeURLMissing, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeTypeMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeTypeMissing, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeValidWebsiteType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeValidWebsiteType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeInValidType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeInValidType, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeMixedRefs", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeMixedRefs, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxCompSourceCodeWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompSourceCodeWrongType, sbom.Signature{})
		require.Error(t, err)
	})

}

var cdxSBOMPrimaryComponentValid = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "bom-ref": "app-1.0",
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  },
  "components": []
}
`)

var spdxSBOMPrimaryComponentValid = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-App",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxSBOMPrimaryComponentAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {
      "type": "application",
      "name": "my-app",
      "version": "1.0"
    }
  ]
}
`)

var spdxSBOMPrimaryComponentAbsent = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": []
}
`)

var cdxSBOMPrimaryComponentMissing = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var cdxSBOMPrimaryComponentEmptyObject = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {}
  },
  "components": []
}
`)

var cdxSBOMPrimaryComponentMissingName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "version": "1.0"
    }
  },
  "components": []
}
`)

var cdxSBOMPrimaryComponentEmptyName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "type": "application",
      "name": "",
      "version": "1.0"
    }
  },
  "components": []
}
`)

var cdxSBOMPrimaryComponentWrongType = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": []
  },
  "components": []
}
`)

func TestSBOMWithPrimaryComponent(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxSBOMPrimaryComponentValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMPrimaryComponentValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPrimaryComponentValid", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPrimaryComponentValid, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMPrimaryComponentAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMPrimaryComponentAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxSBOMPrimaryComponentAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMPrimaryComponentAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	// ERROR/BUG: FIX IT
	t.Run("cdxSBOMPrimaryComponentEmptyObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMPrimaryComponentEmptyObject, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMPrimaryComponentMissingName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMPrimaryComponentMissingName, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMPrimaryComponentEmptyName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMPrimaryComponentEmptyName, sbom.Signature{})
		require.NoError(t, err)

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxSBOMPrimaryComponentWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMPrimaryComponentWrongType, sbom.Signature{})
		require.Error(t, err)
	})
}

// CompWithDependencies
var cdxDependencyDeclaredComplete = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "bom-ref": "app",
      "type": "application",
      "name": "app",
      "version": "1.0"
    }
  },
  "components": [
    {
      "bom-ref": "lib-a",
      "type": "library",
      "name": "lib-a",
      "version": "1.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app",
      "dependsOn": ["lib-a"]
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

var cdxDependencyDeclaredUnknown = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "bom-ref": "lib-a",
      "type": "library",
      "name": "lib-a",
      "version": "1.0"
    }
  ],
  "dependencies": [
    {
      "ref": "root",
      "dependsOn": ["lib-a"]
    }
  ],
  "compositions": [
    {
      "aggregate": "unknown",
      "dependencies": ["root"]
    }
  ]
}
`)

var cdxDepsDeclaredIncomplete = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "bom-ref": "lib-a",
      "type": "library",
      "name": "lib-a",
      "version": "1.0"
    }
  ],
  "dependencies": [
    {
      "ref": "root",
      "dependsOn": ["lib-a"]
    }
  ],
  "compositions": [
    {
      "aggregate": "incomplete",
      "dependencies": ["root"]
    }
  ]
}
`)

var cdxDependencyDeclarationAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "bom-ref": "lib-a",
      "type": "library",
      "name": "lib-a",
      "version": "1.0"
    }
  ],
  "dependencies": [
    {
      "ref": "root",
      "dependsOn": ["lib-a"]
    }
  ],
  "compositions": [
    {
      "aggregate": "incomplete",
      "dependencies": ["root"]
    }
  ]
}
`)

var spdxComponentValidDependency = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-App",
      "name": "my-app",
      "versionInfo": "1.0"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-App",
      "relationshipType": "DESCRIBES"
    }
  ]
}
`)

var cdxTwoComponentsWithDependenciesDeclaredComplete = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "metadata": {
    "component": {
      "bom-ref": "app",
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "bom-ref": "lib-a",
      "type": "library",
      "name": "lib-a",
      "version": "1.0.0"
    },
    {
      "bom-ref": "lib-b",
      "type": "library",
      "name": "lib-b",
      "version": "2.0.0"
    }
  ],
  "dependencies": [
    {
      "ref": "app",
      "dependsOn": ["lib-a", "lib-b"]
    },
    {
      "ref": "lib-a",
      "dependsOn": ["lib-b"]
    }
  ],
  "compositions": [
    {
      "aggregate": "complete",
      "dependencies": ["app"]
    },
    {
      "aggregate": "complete",
      "dependencies": ["lib-a"]
    }
  ]
}
`)

var cdxDependencyAbsent = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "bom-ref": "lib-a",
      "type": "library",
      "name": "lib-a",
      "version": "1.0"
    }
  ]
}
`)

func TestCompWithDependencies(t *testing.T) {
	ctx := context.Background()

	t.Run("cdxDependencyAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDependencyAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDependencyDeclaredComplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDependencyDeclaredComplete, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "dependency completeness declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("spdxComponentValidDependency", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxComponentValidDependency, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "dependency completeness declared N/A (SPDX)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDependencyDeclaredUnknown", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDependencyDeclaredUnknown, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDepsDeclaredIncomplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDepsDeclaredIncomplete, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxDependencyDeclarationAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxDependencyDeclarationAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "no components declare dependencies", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("cdxTwoComponentsWithDependenciesDeclaredComplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxTwoComponentsWithDependenciesDeclaredComplete, sbom.Signature{})
		require.NoError(t, err)

		got := CompWithDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "dependency completeness declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}
