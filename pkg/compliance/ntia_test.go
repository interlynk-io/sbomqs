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

package compliance

import (
	"context"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cdxSBOMWithValidSpecAndVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [
      {
        "vendor": "anchore",
        "name": "syft",
        "version": "0.95.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "pkg",
      "version": "1.0.0",
      "bom-ref": "pkg@1.0.0"
    }
  ]
}
`)

var spdxSBOMWithValidSpecAndVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "test-doc",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "https://example.com/test",
  "creationInfo": {
    "created": "2025-01-01T00:00:00Z",
    "creators": ["Tool: syft v0.95.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Pkg",
      "name": "pkg",
      "versionInfo": "1.0.0"
    }
  ]
}
`)

var spdxSBOMWithInvalidSpecVersion = []byte(`
{
  "spdxVersion": SPDX-0.3,
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "bad-doc"
}
`)

var spdxSBOMWithMissingSpecVersion = []byte(`
{
  "spdxVersion": "",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "bad-doc"
}
`)

var cdxSBOMWithInvalidVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "version": 0.1
}
`)

var cdxSBOMWithMissingVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "version": ""
}
`)

var cdxSBOMWithMissingSpec = []byte(`
{
  "bomFormat": "",
  "version": 1.6
}
`)

var cdxSBOMWithInvalidSpec = []byte(`
{
  "bomFormat": "CycloneFXZ",
  "version": 1.6
}
`)

func TestNTIASBOMAutomationSpec(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMWithValidSpecAndVersion
	t.Run("cdxSBOMWithValidSpecAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithValidSpecAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaMachineFormatAutomationSpec(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_MACHINE_FORMAT, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "cyclonedx, json", got.CheckValue)
	})
	// spdxSBOMWithValidSpecAndVersion
	t.Run("spdxSBOMWithValidSpecAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithValidSpecAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaMachineFormatAutomationSpec(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_MACHINE_FORMAT, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "spdx, json", got.CheckValue)
	})

	t.Run("spdxSBOMWithInvalidSpecVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithInvalidSpecVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("spdxSBOMWithMissingSpecVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMWithMissingSpecVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMWithInvalidVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithInvalidVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMWithMissingVersion", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithMissingVersion, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMWithMissingSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithMissingSpec, sbom.Signature{})
		require.Error(t, err)
	})

	t.Run("cdxSBOMWithInvalidSpec", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMWithInvalidSpec, sbom.Signature{})
		require.Error(t, err)
	})
}

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
  packages: []
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

var cdxSBOMToolsWithNameAndVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:7b6b8f92-9c4a-4c89-8c36-5b12f0d8a111",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "Awesome Vendor",
          "name": "Awesome Tool",
          "version": "9.1.2"
        },
        {
          "type": "application",
          "group": "Another Vendor",
          "name": "Better Tool",
          "version": "2.4.0"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolsWithNameAndVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "Example SPDX SBOM",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2024-01-01T10:00:00Z",
    "creators": [
      "Tool: Awesome Tool-9.1.2",
      "Tool: Better Tool-2.4.0"
    ]
  },
  "packages": []
}
`)

var cdxSBOMToolsWithName = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:7b6b8f92-9c4a-4c89-8c36-5b12f0d8a111",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "Awesome Vendor",
          "name": "Awesome Tool"
        },
        {
          "type": "application",
          "group": "Another Vendor",
          "name": "Better Tool"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolsWithName = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "Example SPDX SBOM",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2024-01-01T10:00:00Z",
    "creators": [
      "Tool: Awesome Tool",
      "Tool: Better Tool"
    ]
  },
  "packages": []
}
`)

var cdxSBOMToolsWithVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:7b6b8f92-9c4a-4c89-8c36-5b12f0d8a111",
  "version": 1,
  "metadata": {
    "tools": {
      "components": [
        {
          "type": "application",
          "group": "Awesome Vendor",
          "version": "9.1.2"
        },
        {
          "type": "application",
          "group": "Another Vendor",
          "version": "2.4.0"
        }
      ]
    }
  },
  "components": []
}
`)

var spdxSBOMToolsWithVersion = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "Example SPDX SBOM",
  "dataLicense": "CC0-1.0",
  "creationInfo": {
    "created": "2024-01-01T10:00:00Z",
    "creators": [
      "Tool: -9.1.2",
      "Tool: -2.4.0"
    ]
  },
  "packages": []
}
`)

func TestNTIASBOMAutomationTool(t *testing.T) {
	ctx := context.Background()

	// cdxSBOMToolWithNameAndVersion
	t.Run("cdxSBOMToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool-9.1.2", got.CheckValue)
	})

	// spdxSBOMToolWithNameAndVersion
	t.Run("spdxSBOMToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool-9.1.2", got.CheckValue)
	})

	// cdxSBOMToolWithName
	t.Run("cdxSBOMToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool", got.CheckValue)
	})

	// spdxSBOMToolWithName
	t.Run("spdxSBOMToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool", got.CheckValue)
	})

	// cdxSBOMToolWithVersion
	t.Run("cdxSBOMToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "SBOM tool version declared without tool name", got.CheckValue)
	})

	// spdxSBOMToolWithVersion
	t.Run("spdxSBOMToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "SBOM tool version declared without tool name", got.CheckValue)
	})

	// cdxSBOMToolAbsent
	t.Run("cdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// spdxSBOMToolAbsent
	t.Run("spdxSBOMToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// cdxSBOMToolMissing
	t.Run("cdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// spdxSBOMToolMissing
	t.Run("spdxSBOMToolMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// cdxSBOMDeprecatedToolWithNameAndVersion
	t.Run("cdxSBOMDeprecatedToolWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool-9.1.2", got.CheckValue)
	})

	// cdxSBOMDeprecatedToolWithName
	t.Run("cdxSBOMDeprecatedToolWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool", got.CheckValue)
	})

	// cdxSBOMDeprecatedToolWithVersion
	t.Run("cdxSBOMDeprecatedToolWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "SBOM tool version declared without tool name", got.CheckValue)
	})

	// cdxSBOMDeprecatedToolWithNameAndVersionEmptyString
	t.Run("cdxSBOMDeprecatedToolWithNameAndVersionEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolWithNameAndVersionEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// spdxSBOMToolWithEmptyString
	t.Run("spdxSBOMToolWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// cdxSBOMDeprecatedToolAbsent
	t.Run("cdxSBOMDeprecatedToolAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMDeprecatedToolAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// cdxSBOMToolWrongType
	t.Run("cdxSBOMToolWrongType", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolWrongType, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "no SBOM generation tool declared", got.CheckValue)
	})

	// spdxSBOMToolWrongType
	t.Run("spdxSBOMToolWrongType", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolWrongType, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMToolsWithNameAndVersion
	t.Run("cdxSBOMToolsWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolsWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool-9.1.2; Better Tool-2.4.0", got.CheckValue)
	})

	// spdxSBOMToolsWithNameAndVersion
	t.Run("spdxSBOMToolsWithNameAndVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolsWithNameAndVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool-9.1.2; Better Tool-2.4.0", got.CheckValue)
	})

	// cdxSBOMToolsWithName
	t.Run("cdxSBOMToolsWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolsWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool; Better Tool", got.CheckValue)
	})

	// spdxSBOMToolsWithName
	t.Run("spdxSBOMToolsWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolsWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "Awesome Tool; Better Tool", got.CheckValue)
	})

	// cdxSBOMToolsWithVersion
	t.Run("cdxSBOMToolsWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMToolsWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "SBOM tool version declared without tool name", got.CheckValue)
	})

	// spdxSBOMToolsWithVersion
	t.Run("spdxSBOMToolsWithVersion", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMToolsWithVersion, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMGenerationAutomationTool(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_AUTOMATION_TOOL, got.CheckKey)
		assert.Equal(t, "Automation Support", got.ID)
		assert.Equal(t, "SBOM tool version declared without tool name", got.CheckValue)
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

var spdxSBOMAuthorWithNameAndEmail = []byte(`
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

var cdxSBOMAuthorsWithEmptyString = []byte(`
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

var spdxSBOMAuthorsWithEmptyString = []byte(`
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

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: Samantha Wright", got.CheckValue)
	})

	// spdxSBOMAuthorWithNameAndEmail
	t.Run("spdxSBOMAuthorWithNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: Samantha Wright", got.CheckValue)
	})

	// spdxSBOMAuthorWithOrganizationNameAndEmail
	t.Run("spdxSBOMAuthorWithOrganizationNameAndEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationNameAndEmail, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: Samantha Wright", got.CheckValue)
	})

	// cdxSBOMAuthorWithEmail
	t.Run("cdxSBOMAuthorWithEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithEmail, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: samantha.wright@example.com", got.CheckValue)
	})

	// spdxSBOMAuthorWithPersonEmail
	t.Run("spdxSBOMAuthorWithPersonEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonEmail, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: samantha.wright@example.com", got.CheckValue)
	})

	// spdxSBOMAuthorWithOrganizationEmail
	t.Run("spdxSBOMAuthorWithOrganizationEmail", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationEmail, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: samantha.wright@example.com", got.CheckValue)
	})

	// cdxSBOMAuthorWithName
	t.Run("cdxSBOMAuthorWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: Samantha Wright", got.CheckValue)
	})

	// spdxSBOMAuthorWithPersonName
	t.Run("spdxSBOMAuthorWithPersonName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithPersonName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: Samantha Wright", got.CheckValue)
	})

	// spdxSBOMAuthorWithOrganizationName
	t.Run("spdxSBOMAuthorWithOrganizationName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorWithOrganizationName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author declared explicitly: Samantha Wright", got.CheckValue)
	})

	// cdxSBOMAuthorsAbsent
	t.Run("cdxSBOMAuthorsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// spdxSBOMAuthorAbsent
	t.Run("spdxSBOMAuthorAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMAuthorMissing
	t.Run("cdxSBOMAuthorMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// spdxSBOMAuthorPersonMissing
	t.Run("spdxSBOMAuthorPersonMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorPersonMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// spdxSBOMAuthorOrganizationMissing
	t.Run("spdxSBOMAuthorOrganizationMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorOrganizationMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMAuthorsWithEmptyString
	t.Run("cdxSBOMAuthorsWithEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// spdxSBOMAuthorsWithEmptyString
	t.Run("spdxSBOMAuthorsWithEmptyString", func(t *testing.T) {
		_, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyString, sbom.Signature{})
		require.Error(t, err)
	})

	// cdxSBOMAuthorsWithEmptyArray
	t.Run("cdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMAuthorsWithEmptyArrayObject
	t.Run("cdxSBOMAuthorsWithEmptyArrayObject", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMAuthorsWithEmptyArrayObject, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// spdxSBOMAuthorsWithEmptyArray
	t.Run("spdxSBOMAuthorsWithEmptyArray", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxSBOMAuthorsWithEmptyArray, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
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

	// cdxSBOMSupplierWithNameAndURL
	t.Run("cdxSBOMSupplierWithNameAndURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameAndURL, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author inferred from supplier (fallback): Acme, Inc.", got.CheckValue)
	})

	// cdxSBOMSupplierWithName
	t.Run("cdxSBOMSupplierWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author inferred from supplier (fallback): Acme, Inc.", got.CheckValue)
	})

	// cdxSBOMSupplierWithURL
	t.Run("cdxSBOMSupplierWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author inferred from supplier (fallback): https://example.com", got.CheckValue)
	})

	// cdxSBOMSupplierMissing
	t.Run("cdxSBOMSupplierMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMSupplierAbsent
	t.Run("cdxSBOMSupplierAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMSupplierWithNameEmptyString
	t.Run("cdxSBOMSupplierWithNameEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMSupplierWithURLEmptyString
	t.Run("cdxSBOMSupplierWithURLEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithURLEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMSupplierWithNameWhitespace
	t.Run("cdxSBOMSupplierWithNameWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMSupplierWithNameWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
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

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author inferred from manufacturer (fallback): Acme, Inc.", got.CheckValue)
	})

	// cdxSBOMManufacturerWithName
	t.Run("cdxSBOMManufacturerWithName", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufacturerWithName, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author inferred from manufacturer (fallback): Acme, Inc.", got.CheckValue)
	})

	// cdxSBOMManufactureWithURL
	t.Run("cdxSBOMManufactureWithURL", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithURL, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "author inferred from manufacturer (fallback): https://example.com", got.CheckValue)
	})

	// cdxSBOMManufactureMissing
	t.Run("cdxSBOMManufactureMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMManufactureAbsent
	t.Run("cdxSBOMManufactureAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMManufactureWithNameEmptyString
	t.Run("cdxSBOMManufactureWithNameEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithNameEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMManufactureWithURLEmptyString
	t.Run("cdxSBOMManufactureWithURLEmptyString", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithURLEmptyString, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
	})

	// cdxSBOMManufactureWithNameWhitespace
	t.Run("cdxSBOMManufactureWithNameWhitespace", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxSBOMManufactureWithNameWhitespace, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSbomAuthor(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_CREATOR, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "SBOM author absent", got.CheckValue)
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

func TestNTIASBOMDependenciesRelationships(t *testing.T) {
	ctx := context.Background()

	// cdxCompWithPrimaryRelationships
	t.Run("cdxCompWithPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component declares 2 direct dependencies", got.CheckValue)
	})

	// spdxCompWithPrimaryRelationships
	t.Run("spdxCompWithPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component declares 2 direct dependencies", got.CheckValue)
	})

	// cdxCompWithNoPrimaryRelationships
	t.Run("cdxCompWithNoPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithNoPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "no dependency relationships or completeness declared for primary component", got.CheckValue)
	})

	// spdxCompWithNoPrimaryRelationships
	t.Run("spdxCompWithNoPrimaryRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithNoPrimaryRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "no dependency relationships or completeness declared for primary component", got.CheckValue)
	})

	// cdxCompWithPrimaryComponentMissing
	t.Run("cdxCompWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component not declared", got.CheckValue)
	})

	// spdxCompWithPrimaryComponentMissing
	t.Run("spdxCompWithPrimaryComponentMissing", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxCompWithPrimaryComponentMissing, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component not declared", got.CheckValue)
	})

	// cdxCompWithPrimaryRelationshipsAndDeclaredRelationships
	t.Run("cdxCompWithPrimaryRelationshipsAndDeclaredRelationships", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryRelationshipsAndDeclaredRelationships, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component declares 2 direct dependencies", got.CheckValue)
	})

	// cdxCompWithPrimaryDeclaredRelationshipsComplete
	t.Run("cdxCompWithPrimaryDeclaredRelationshipsComplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryDeclaredRelationshipsComplete, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component declares dependencies completeness complete", got.CheckValue)
	})

	// cdxCompWithPrimaryDeclaredRelationshipsUnknown
	t.Run("cdxCompWithPrimaryDeclaredRelationshipsUnknown", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryDeclaredRelationshipsUnknown, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component declares dependencies completeness unknown", got.CheckValue)
	})

	// cdxCompWithPrimaryDeclaredRelationshipsIncomplete
	t.Run("cdxCompWithPrimaryDeclaredRelationshipsIncomplete", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithPrimaryDeclaredRelationshipsIncomplete, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "primary component declares dependencies completeness incomplete", got.CheckValue)
	})

	// cdxCompWithRelationshipsAbsent
	t.Run("cdxCompWithRelationshipsAbsent", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxCompWithRelationshipsAbsent, sbom.Signature{})
		require.NoError(t, err)

		got := ntiaSBOMDependencyRelationships(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, SBOM_DEPENDENCY_RELATIONSHIP, got.CheckKey)
		assert.Equal(t, "Required Document-level", got.ID)
		assert.Equal(t, "no dependency relationships or completeness declared for primary component", got.CheckValue)
	})

}

// func createSpdxDummyDocumentNtia() sbom.Document {
// 	s := sbom.NewSpec()
// 	s.Version = "SPDX-2.3"
// 	s.SpecType = "spdx"
// 	s.Format = "json"
// 	s.CreationTimestamp = "2023-05-04T09:33:40Z"

// 	var creators []sbom.GetTool
// 	creator := sbom.Tool{
// 		Name: "syft",
// 	}
// 	creators = append(creators, creator)

// 	pack1 := sbom.NewComponent()
// 	pack1.Version = "v0.7.1"
// 	pack1.Name = "tool-golang"
// 	pack1.ID = "github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1"

// 	pack2 := sbom.NewComponent()
// 	pack2.Version = "v1.0.1"
// 	pack2.Name = "spdx-gordf"
// 	pack2.ID = "github/spdx/gordf@b735bd5aac89fe25cad4ef488a95bc00ea549edd"

// 	supplier := sbom.Supplier{
// 		Email: "hello@interlynk.io",
// 	}
// 	pack1.Supplier = supplier

// 	extRef := sbom.ExternalReference{
// 		RefType: "purl",
// 	}

// 	var primary sbom.PrimaryComponentInfo
// 	primary.ID = pack1.ID
// 	primary.Name = pack1.Name
// 	primary.Version = pack1.Version
// 	primary.Type = "application"
// 	primary.Present = true

// 	var rel sbom.Relationship

// 	rel.From = pack1.ID
// 	rel.To = pack2.ID
// 	rel.Type = "DEPENDS_ON"

// 	var relations []sbom.GetRelationship
// 	relations = append(relations, rel)

// 	var externalReferences []sbom.GetExternalReference
// 	externalReferences = append(externalReferences, extRef)
// 	pack1.ExternalRefs = externalReferences

// 	var packages []sbom.GetComponent
// 	packages = append(packages, pack1, pack2)

// 	doc := sbom.SpdxDoc{
// 		SpdxSpec:         s,
// 		Comps:            packages,
// 		SpdxTools:        creators,
// 		Relationships:    relations,
// 		PrimaryComponent: primary,
// 	}
// 	return doc
// }

// type desiredNtia struct {
// 	score  float64
// 	result string
// 	key    int
// 	id     string
// }

// func TestNtiaSpdxSbomPass(t *testing.T) {
// 	doc := createSpdxDummyDocumentNtia()
// 	testCases := []struct {
// 		name     string
// 		actual   *db.Record
// 		expected desiredNtia
// 	}{
// 		{
// 			name:   "AutomationSpec",
// 			actual: ntiaAutomationSpec(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "spdx, json",
// 				key:    SBOM_MACHINE_FORMAT,
// 				id:     "Automation Support",
// 			},
// 		},
// 		{
// 			name:   "SbomCreator",
// 			actual: ntiaSbomCreator(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "syft",
// 				key:    SBOM_CREATOR,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "SbomCreatedTimestamp",
// 			actual: ntiaSbomCreatedTimestamp(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "2023-05-04T09:33:40Z",
// 				key:    SBOM_TIMESTAMP,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "SbomDependency",
// 			actual: ntiaSBOMRelationships(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "primary component declares 1 direct dependencies",
// 				key:    SBOM_DEPENDENCY,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "ComponentCreator",
// 			actual: ntiaComponentCreator(doc, doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "hello@interlynk.io",
// 				key:    COMP_CREATOR,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentName",
// 			actual: ntiaComponentName(doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "tool-golang",
// 				key:    COMP_NAME,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentVersion",
// 			actual: ntiaComponentVersion(doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "v0.7.1",
// 				key:    COMP_VERSION,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentOtherUniqIDs",
// 			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "purl:(1/1)",
// 				key:    COMP_OTHER_UNIQ_IDS,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 	}

// 	for _, test := range testCases {
// 		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
// 	}
// }

// func createCdxDummyDocumentNtia() sbom.Document {
// 	cdxSpec := sbom.NewSpec()
// 	cdxSpec.Version = "1.4"
// 	cdxSpec.SpecType = "cyclonedx"
// 	cdxSpec.CreationTimestamp = "2023-05-04T09:33:40Z"
// 	cdxSpec.Format = "xml"

// 	var authors []sbom.GetAuthor
// 	author := sbom.Author{
// 		Email: "hello@interlynk.io",
// 	}
// 	authors = append(authors, author)

// 	comp1 := sbom.NewComponent()
// 	comp1.Version = "v0.7.1"
// 	comp1.Name = "tool-golang"
// 	comp1.ID = "github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1"

// 	comp2 := sbom.NewComponent()
// 	comp2.Version = "v1.0.1"
// 	comp2.Name = "spdx-gordf"
// 	comp2.ID = "github/spdx/gordf@b735bd5aac89fe25cad4ef488a95bc00ea549edd"

// 	supplier := sbom.Supplier{
// 		Email: "hello@interlynk.io",
// 	}
// 	comp1.Supplier = supplier

// 	npurl := purl.NewPURL("vivek")

// 	comp1.Purls = []purl.PURL{npurl}

// 	extRef := sbom.ExternalReference{
// 		RefType: "purl",
// 	}

// 	var externalReferences []sbom.GetExternalReference
// 	externalReferences = append(externalReferences, extRef)
// 	comp1.ExternalRefs = externalReferences

// 	var components []sbom.GetComponent
// 	components = append(components, comp1, comp2)

// 	var primary sbom.PrimaryComponentInfo
// 	primary.ID = comp1.ID
// 	primary.Name = comp1.Name
// 	primary.Version = comp1.Version
// 	primary.Type = "application"
// 	primary.Present = true

// 	var dep sbom.Relationship
// 	dep.From = comp1.ID
// 	dep.To = comp2.ID
// 	dep.Type = "DEPENDS_ON"

// 	var relationships []sbom.GetRelationship
// 	relationships = append(relationships, dep)

// 	doc := sbom.CdxDoc{
// 		CdxSpec:          cdxSpec,
// 		Comps:            components,
// 		CdxAuthors:       authors,
// 		Relationships:    relationships,
// 		PrimaryComponent: primary,
// 	}
// 	return doc
// }

// func TestNtiaCdxSbomPass(t *testing.T) {
// 	doc := createCdxDummyDocumentNtia()
// 	testCases := []struct {
// 		name     string
// 		actual   *db.Record
// 		expected desiredNtia
// 	}{
// 		{
// 			name:   "AutomationSpec",
// 			actual: ntiaAutomationSpec(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "cyclonedx, xml",
// 				key:    SBOM_MACHINE_FORMAT,
// 				id:     "Automation Support",
// 			},
// 		},
// 		{
// 			name:   "SbomCreator",
// 			actual: ntiaSbomAuthor(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "hello@interlynk.io",
// 				key:    SBOM_CREATOR,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "SbomCreatedTimestamp",
// 			actual: ntiaSbomCreatedTimestamp(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "2023-05-04T09:33:40Z",
// 				key:    SBOM_TIMESTAMP,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "SbomDependency",
// 			actual: ntiaSBOMRelationships(doc),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "primary component declares 1 direct dependencies",
// 				key:    SBOM_DEPENDENCY,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "ComponentCreator",
// 			actual: ntiaComponentCreator(doc, doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "hello@interlynk.io",
// 				key:    COMP_CREATOR,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentName",
// 			actual: ntiaComponentName(doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "tool-golang",
// 				key:    COMP_NAME,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentVersion",
// 			actual: ntiaComponentVersion(doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "v0.7.1",
// 				key:    COMP_VERSION,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentOtherUniqIDs",
// 			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  10.0,
// 				result: "vivek",
// 				key:    COMP_OTHER_UNIQ_IDS,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 	}
// 	for _, test := range testCases {
// 		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
// 	}
// }

// func createSpdxDummyDocumentFailNtia() sbom.Document {
// 	s := sbom.NewSpec()
// 	s.Version = "SPDX-4.0"
// 	s.SpecType = "swid"
// 	s.Format = "fjson"
// 	s.CreationTimestamp = "2023-05-04"

// 	var creators []sbom.GetTool
// 	creator := sbom.Tool{
// 		Name: "",
// 	}
// 	creators = append(creators, creator)

// 	pack := sbom.NewComponent()
// 	pack.Version = ""
// 	pack.Name = ""

// 	supplier := sbom.Supplier{
// 		Email: "",
// 	}
// 	pack.Supplier = supplier

// 	extRef := sbom.ExternalReference{
// 		RefType: "purl",
// 	}

// 	var externalReferences []sbom.GetExternalReference
// 	externalReferences = append(externalReferences, extRef)
// 	pack.ExternalRefs = externalReferences

// 	var packages []sbom.GetComponent
// 	packages = append(packages, pack)

// 	depend := sbom.Relationship{
// 		From: "",
// 		To:   "",
// 		Type: "",
// 	}

// 	var dependencies []sbom.GetRelationship
// 	dependencies = append(dependencies, depend)

// 	doc := sbom.SpdxDoc{
// 		SpdxSpec:      s,
// 		Comps:         packages,
// 		SpdxTools:     creators,
// 		Relationships: dependencies,
// 	}
// 	return doc
// }

// func TestNTIASbomFail(t *testing.T) {
// 	doc := createSpdxDummyDocumentFailNtia()
// 	testCases := []struct {
// 		name     string
// 		actual   *db.Record
// 		expected desiredNtia
// 	}{
// 		{
// 			name:   "AutomationSpec",
// 			actual: ntiaAutomationSpec(doc),
// 			expected: desiredNtia{
// 				score:  0.0,
// 				result: "swid, fjson",
// 				key:    SBOM_MACHINE_FORMAT,
// 				id:     "Automation Support",
// 			},
// 		},
// 		{
// 			name:   "SbomCreator",
// 			actual: ntiaSbomCreator(doc),
// 			expected: desiredNtia{
// 				score:  0.0,
// 				result: "",
// 				key:    SBOM_CREATOR,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "SbomCreatedTimestamp",
// 			actual: ntiaSbomCreatedTimestamp(doc),
// 			expected: desiredNtia{
// 				score:  0.0,
// 				result: "2023-05-04",
// 				key:    SBOM_TIMESTAMP,
// 				id:     "SBOM Data Fields",
// 			},
// 		},
// 		{
// 			name:   "ComponentCreator",
// 			actual: ntiaComponentCreator(doc, doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  0.0,
// 				result: "",
// 				key:    COMP_CREATOR,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},

// 		{
// 			name:   "ComponentName",
// 			actual: ntiaComponentName(doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  0.0,
// 				result: "",
// 				key:    COMP_NAME,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentVersion",
// 			actual: ntiaComponentVersion(doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  0.0,
// 				result: "",
// 				key:    COMP_VERSION,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 		{
// 			name:   "ComponentOtherUniqIDs",
// 			actual: ntiaComponentOtherUniqIDs(doc, doc.Components()[0]),
// 			expected: desiredNtia{
// 				score:  0.0,
// 				result: "",
// 				key:    COMP_OTHER_UNIQ_IDS,
// 				id:     common.UniqueElementID(doc.Components()[0]),
// 			},
// 		},
// 	}

// 	for _, test := range testCases {
// 		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
// 		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
// 	}
// }
