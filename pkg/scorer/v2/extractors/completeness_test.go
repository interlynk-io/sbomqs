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
	"fmt"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
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

type miniComp2 struct {
	id               string
	name             string
	version          string
	srcURL           string
	supplierName     string
	supplierEmail    string
	supplierURL      string
	RelElementA      string
	RelElementB      string
	RelType          string
	primaryPurpose   string
	hasRelationships bool
	depsCount        int
}

type spdxDocOpts2 struct {
	namespace   string
	withPrimary bool
	comps       []miniComp2
}

type cdxDocOpts2 struct {
	uri         string
	withPrimary bool
	comps       []miniComp2
}

func makeSPDXDocForCompleteness(opts spdxDocOpts2) sbom.Document {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.Spdxid = "DOCUMENT"
	s.Namespace = opts.namespace
	s.CreationTimestamp = "2025-01-01T00:00:00Z"

	var comps []sbom.GetComponent
	var deps []sbom.GetRelation

	for _, c := range opts.comps {
		p := sbom.NewComponent()
		p.ID = c.id
		p.Name = c.name
		p.Version = c.version
		p.SourceCodeURL = c.srcURL
		if c.supplierName != "" || c.supplierEmail != "" || c.supplierURL != "" {
			p.Supplier = sbom.Supplier{Name: c.supplierName, Email: c.supplierEmail, URL: c.supplierURL}
		}
		p.Purpose = c.primaryPurpose
		p.HasRelationships = c.hasRelationships
		p.Count = c.depsCount

		var dep sbom.Relation
		dep.From = c.RelElementA
		dep.To = c.RelElementB

		deps = append(deps, dep)
		comps = append(comps, p)
	}

	pc := sbom.PrimaryComp{}
	pc.Present = opts.withPrimary

	return sbom.SpdxDoc{
		SpdxSpec:         s,
		Comps:            comps,
		Rels:             deps,
		PrimaryComponent: pc,
	}
}

func TestSBOMWithDeclaredCompleteness_ForSPDX(t *testing.T) {
	doc := makeSPDXDocForCompleteness(spdxDocOpts2{
		withPrimary: true,
		comps: []miniComp2{
			{id: "SPDXRef-A", name: "a", version: "1.0.0", hasRelationships: false, depsCount: 0},
		},
	})

	got := SBOMWithDeclaredCompleteness(doc)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "N/A (SPDX)", got.Desc)
}

func TestCompWithDependencies(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoDependencies", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", hasRelationships: false, depsCount: 0},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", hasRelationships: false, depsCount: 0},
			},
		})

		got := CompWithDependencies(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "2 min 1 dependency (completeness unknown)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithDependency", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", hasRelationships: true, depsCount: 2},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", hasRelationships: false, depsCount: 0},
			},
		})
		got := CompWithDependencies(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "1 min 1 dependency (completeness unknown)", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithDependency", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", hasRelationships: true, depsCount: 2},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", hasRelationships: true, depsCount: 3},
			},
		})
		got := CompWithDependencies(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "0 min 1 dependency (completeness unknown)", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithPrimaryComponent(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: false,
		})

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add primary component", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithPrimaryComponent", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
		})

		got := SBOMWithPrimaryComponent(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithSourceCode(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoSourceCodeURL", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})

		got := CompWithSourceCode(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithSourceCodeURL", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", srcURL: "https://github.com/demo/foo"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})
		got := CompWithSourceCode(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithSourceCodeURL", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", srcURL: "https://github.com/demo/foo"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", srcURL: "https://github.com/demo/bar"},
			},
		})
		got := CompWithSourceCode(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithSupplier(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoSupplier", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})

		got := CompWithSupplier(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithSupplier", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", supplierName: "redhat", supplierEmail: "hello@redhat.com"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})
		got := CompWithSupplier(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithSupplier", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", supplierName: "redhat", supplierEmail: "hello@redhat.com"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", supplierName: "ubuntu", supplierEmail: "hello@ubuntu.com"},
			},
		})
		got := CompWithSupplier(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

func TestCompWithPackageType(t *testing.T) {
	t.Run("NoComponents", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{})

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "N/A (no components)", got.Desc)
		assert.True(t, got.Ignore)
	})

	t.Run("ComponentsWithNoPackageType", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})

		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 0.0, got.Score, 1e-9)
		assert.Equal(t, "add to 2 components", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("OneComponentWithPackageType", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", primaryPurpose: "container"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0"},
			},
		})
		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 5.0, got.Score, 1e-9)
		assert.Equal(t, "add to 1 component", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ALLComponentWithPackageType", func(t *testing.T) {
		doc := makeSPDXDocForCompleteness(spdxDocOpts2{
			withPrimary: true,
			comps: []miniComp2{
				{id: "SPDXRef-A", name: "a", version: "1.0.0", primaryPurpose: "library"},
				{id: "SPDXRef-B", name: "b", version: "2.0.0", primaryPurpose: "application"},
			},
		})
		got := CompWithPackagePurpose(doc)

		assert.InDelta(t, 10.0, got.Score, 1e-9)
		assert.Equal(t, "complete", got.Desc)
		assert.False(t, got.Ignore)
	})
}

type miniComposition struct {
	scope           sbom.CompositionScope
	aggregate       sbom.CompositionAggregate
	dependencies    []string
	assemblies      []string
	vulnerabilities []string
}

func makeCDXDocForCompleteness(comps []miniComp2, compositions []miniComposition) sbom.Document {
	var components []sbom.GetComponent
	for _, c := range comps {
		p := sbom.NewComponent()
		p.ID = c.id
		p.Name = c.name
		p.Version = c.version
		components = append(components, p)
	}

	var csts []sbom.GetComposition
	for i, mc := range compositions {

		cst := sbom.NewComposition(
			fmt.Sprintf("cmp-%d", i),
			mc.scope,
			mc.aggregate,
			mc.dependencies,
			mc.assemblies,
			mc.vulnerabilities,
		)

		csts = append(csts, cst)
	}

	spec := sbom.NewSpec()
	spec.SpecType = string(sbom.SBOMSpecCDX)
	spec.Version = "1.6"

	return sbom.CdxDoc{
		CdxSpec:      spec,
		Comps:        components,
		Compositions: csts,
	}
}

func TestCompWithDeclaredCompleteness_NoComponents(t *testing.T) {
	doc := makeCDXDocForCompleteness(nil, nil)

	got := CompWithDeclaredCompleteness(doc)

	assert.True(t, got.Ignore)
	assert.Equal(t, "N/A (no components)", got.Desc)
}

func TestCompWithDeclaredCompleteness_SPDX(t *testing.T) {
	doc := makeSPDXDocForCompleteness(spdxDocOpts2{
		withPrimary: true,
		comps: []miniComp2{
			{id: "SPDXRef-A", name: "a", version: "1.0"},
		},
	})

	got := CompWithDeclaredCompleteness(doc)

	assert.True(t, got.Ignore)
	assert.Equal(t, formulae.NonSupportedSPDXField(), got.Desc)
}

func TestCompWithDeclaredCompleteness_NoCompositions(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "B"},
		},
		nil,
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "add to 2 components", got.Desc)
}

func TestCompWithDeclaredCompleteness_GlobalComplete(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "B"},
		},
		[]miniComposition{
			{
				scope:     sbom.ScopeGlobal,
				aggregate: sbom.AggregateComplete,
			},
		},
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 10.0, got.Score, 1e-9)
	assert.Equal(t, "complete", got.Desc)
}

func TestCompWithDeclaredCompleteness_ComponentScoped(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "bom-refB"},
		},
		[]miniComposition{
			{
				scope:        sbom.ScopeDependencies,
				aggregate:    sbom.AggregateComplete,
				dependencies: []string{"bom-refA"},
			},
		},
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
}

func TestCompWithDeclaredCompleteness_Mixed(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "bom-refB"},
		},
		[]miniComposition{
			{
				scope:     sbom.ScopeGlobal,
				aggregate: sbom.AggregateUnknown,
			},
			{
				scope:      sbom.ScopeAssemblies,
				aggregate:  sbom.AggregateComplete,
				assemblies: []string{"bom-refB"},
			},
		},
	)

	got := CompWithDeclaredCompleteness(doc)

	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
}

func TestSBOMWithDeclaredCompleteness_GlobalComplete(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "B"},
		},
		[]miniComposition{
			{
				scope:     sbom.ScopeGlobal,
				aggregate: sbom.AggregateComplete,
			},
		},
	)

	got := SBOMWithDeclaredCompleteness(doc)

	assert.InDelta(t, 10.0, got.Score, 1e-9)
	assert.Equal(t, "SBOM completeness declared", got.Desc)
}

func TestSBOMWithDeclaredCompleteness_GlobalInComplete(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "B"},
		},
		[]miniComposition{
			{
				scope:     sbom.ScopeGlobal,
				aggregate: sbom.CompositionAggregate("incomplete"),
			},
		},
	)

	got := SBOMWithDeclaredCompleteness(doc)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "SBOM completeness not declared", got.Desc)
}

func TestSBOMWithDeclaredCompleteness_NotDefined(t *testing.T) {
	doc := makeCDXDocForCompleteness(
		[]miniComp2{
			{id: "bom-refA"}, {id: "B"},
		}, nil)

	got := SBOMWithDeclaredCompleteness(doc)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "SBOM completeness not declared", got.Desc)
}
