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
	"strings"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── SBOM Data Format ──

var cdxWithDataFormat = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": []
}
`)

var spdxWithDataFormat = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
	"created": "2024-01-15T10:30:00Z",
	"creators": ["Person: John Doe"]
  },
  "packages": []
}
`)

var cdxBelowMinVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.3",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": []
}
`)

func TestNTIA2026SBOMDataFormat(t *testing.T) {
	t.Parallel()

	t.Run("CDX declared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithDataFormat)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMDataFormat(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "CycloneDX is declared SBOM data format", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SPDX declared", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(spdxWithDataFormat)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMDataFormat(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SPDX is declared SBOM data format", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── SBOM Spec Version ──

var cdxWithSpecVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": []
}
`)

var cdxWithoutSpecVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": []
}
`)

func TestNTIA2026SBOMSpecVersion(t *testing.T) {
	t.Parallel()

	t.Run("CDX meets minimum version", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithSpecVersion)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMSpecVersion(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "CycloneDX 1.6 meets minimum version 1.4", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("CDX below minimum version", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxBelowMinVersion)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMSpecVersion(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "CycloneDX 1.3 does not meet minimum version 1.4", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("CDX without spec version", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithoutSpecVersion)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMSpecVersion(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM specification version is not declared", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── SBOM Tool Version ──

var cdxWithToolVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [{"name": "tool-x", "version": "1.0.0"}]
  },
  "components": []
}
`)

var cdxWithToolNoVersion = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [{"name": "tool-x"}]
  },
  "components": []
}
`)

var cdxWithNoTools = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

func TestNTIA2026SBOMToolVersion(t *testing.T) {
	t.Parallel()

	t.Run("tool with version", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithToolVersion)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMToolVersion(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SBOM generation tool version (1.0.0) is declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("tool without version", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithToolNoVersion)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMToolVersion(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM generation tool name is present but version is missing", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("no tools", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithNoTools)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMToolVersion(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM generation tool is not declared", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── SBOM Version ──

func TestNTIA2026SBOMVersion(t *testing.T) {
	t.Parallel()

	t.Run("CDX with URI (serialNumber + version)", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithToolVersion)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMVersion(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SBOM document version is declared via serialNumber and version", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("CDX without version in URI", func(t *testing.T) {
		cdxNoVersion := []byte(`
		{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.6",
		  "components": []
		}
		`)
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxNoVersion)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMVersion(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM document version (serialNumber and version) is not declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SPDX is N/A", func(t *testing.T) {
		spdx := []byte(`
		{
		  "spdxVersion": "SPDX-2.3",
		  "SPDXID": "SPDXRef-DOCUMENT",
		  "creationInfo": {
			"created": "2024-01-15T10:30:00Z",
			"creators": ["Person: John Doe"]
		  },
		  "packages": []
		}
		`)
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(spdx)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMVersion(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SPDX does not support author-assigned SBOM document versions", got.Desc)
		assert.True(t, got.Ignore)
	})
}

// ── SBOM Creation Timestamp ──

var cdxWithTimestamp = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "components": []
}
`)

var cdxWithoutTimestamp = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

func TestNTIA2026SBOMCreationTimestamp(t *testing.T) {
	t.Parallel()

	t.Run("valid timestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithTimestamp)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMCreationTimestamp(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SBOM creation timestamp is valid and RFC 9557-compliant", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("missing timestamp", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithoutTimestamp)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMCreationTimestamp(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM creation timestamp is not declared", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── Generation Context ──

var cdxWithLifecycle = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "lifecycles": [{"phase": "build"}]
  },
  "components": []
}
`)

var cdxWithoutLifecycle = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

var spdxWithComment = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Person: John Doe"],
    "comment": "Generated during CI build"
  },
  "packages": []
}
`)

var spdxWithoutComment = []byte(`
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2024-01-15T10:30:00Z",
    "creators": ["Person: John Doe"]
  },
  "packages": []
}
`)

func TestNTIA2026GenerationContext(t *testing.T) {
	t.Parallel()

	t.Run("CDX with lifecycle", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithLifecycle)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026GenerationContext(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SBOM generation context is build phase", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("CDX without lifecycle", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithoutLifecycle)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026GenerationContext(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM generation context (lifecycle phase) is not declared", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SPDX v2.x with comment", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(spdxWithComment)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026GenerationContext(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SBOM generation context is declared via creationInfo.comment", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SPDX v2.x without comment", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(spdxWithoutComment)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026GenerationContext(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM generation context (creationInfo.comment) is not declared", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── SBOM Authors ──

var cdxWithPersonAuthor = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "authors": [{"name": "Acme Corp", "email": "sbom@acme.com"}]
  },
  "components": []
}
`)

var cdxWithToolAuthorOnly = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "tools": [{"name": "tool-x", "version": "1.0.0"}]
  },
  "components": []
}
`)

var cdxWithNoAuthors = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {},
  "components": []
}
`)

func TestNTIA2026SBOMAuthors(t *testing.T) {
	t.Parallel()

	t.Run("person author present with name", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithPersonAuthor)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMAuthors(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SBOM creator (Acme Corp) provided via authors", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("tool-only author rejected", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithToolAuthorOnly)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMAuthors(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM author (person or organization) is missing; tool entries are not accepted", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("no authors", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithNoAuthors)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026SBOMAuthors(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "SBOM author (person or organization) is missing; tool entries are not accepted", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── Component Producer ──

var cdxWithCompSupplier = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "comp-a",
      "version": "1.0",
      "supplier": {"name": "Supplier Inc", "url": ["https://example.com"]}
    }
  ]
}
`)

var cdxWithCompManufacturer = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "comp-a",
      "version": "1.0",
      "manufacturer": {"name": "Mfg Inc", "url": ["https://mfg.com"]}
    }
  ]
}
`)

var cdxWithCompNoProducer = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "comp-a",
      "version": "1.0"
    }
  ]
}
`)

func TestNTIA2026CompProducer(t *testing.T) {
	t.Parallel()

	t.Run("component with supplier", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompSupplier)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompProducer(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "producer declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("component with manufacturer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompManufacturer)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompProducer(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "producer declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("component with no producer", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompNoProducer)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompProducer(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "no components declare producer", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── Component Hash Algorithm ──

var cdxWithCompHashAlgo = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "comp-a",
      "version": "1.0",
      "hashes": [{"alg": "SHA-256", "content": "abc123"}]
    }
  ]
}
`)

var cdxWithCompHashNoAlgo = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "comp-a",
      "version": "1.0",
      "hashes": [{"content": "abc123"}]
    }
  ]
}
`)

var cdxWithCompNoHashes = []byte(`
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "comp-a",
      "version": "1.0"
    }
  ]
}
`)

func TestNTIA2026CompHashAlgo(t *testing.T) {
	t.Parallel()

	t.Run("component with hash algorithm", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompHashAlgo)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompHashAlgo(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "hash algorithm declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("component with hash but no algorithm", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompHashNoAlgo)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompHashAlgo(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "no components declare hash algorithm", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("component with no hashes", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompNoHashes)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompHashAlgo(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "no components declare hash algorithm", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── Component Name ──

func TestNTIA2026CompName(t *testing.T) {
	t.Parallel()

	t.Run("all components have names", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompSupplier)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompName(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "name declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("component without name", func(t *testing.T) {
		cdxNoName := []byte(`
		{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.6",
		  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		  "version": 1,
		  "components": [
		    {
		      "type": "library",
		      "version": "1.0"
		    }
		  ]
		}
		`)
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxNoName)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompName(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "no components declare name", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── Component Version ──

func TestNTIA2026CompVersion(t *testing.T) {
	t.Parallel()

	t.Run("all components have versions", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompSupplier)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompVersion(doc)
		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "version declared for all components", got.Desc)
		assert.False(t, got.Ignore)
	})
}

// ── Component License ──

func TestNTIA2026CompLicense(t *testing.T) {
	t.Parallel()

	t.Run("component without license", func(t *testing.T) {
		doc, err := sbom.NewSBOMDocument(context.Background(), strings.NewReader(string(cdxWithCompNoHashes)), sbom.Signature{})
		require.NoError(t, err)
		got := NTIA2026CompLicense(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "no components declare declared license", got.Desc)
		assert.False(t, got.Ignore)
	})
}
