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
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/stretchr/testify/assert"
)

func spdxSpecForStructural(ver, fileFmt, spec string) *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = ver
	s.SpecType = spec
	s.Format = fileFmt
	s.Spdxid = "DOCUMENT"
	s.Namespace = "https://example.com/ns"
	return s
}

func cdxSpecForStructural(ver, fileFmt, spec string) *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = ver
	s.SpecType = spec
	s.Format = fileFmt
	s.URI = "urn:uuid:11111111-2222-3333-4444-555555555555"
	return s
}

func Test_SBOMSpec(t *testing.T) {
	t.Run("SupportedSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "json", "spdx")}

		got := SBOMWithSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "spdx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SupportedSPDXUpperCase", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "json", "SPDX")}

		got := SBOMWithSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "spdx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("UnsupportedSpec", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "json", "something-else")}

		got := SBOMWithSpec(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Contains(t, got.Desc, "unsupported spec")
	})
}

func Test_SBOMSpecVersion(t *testing.T) {
	t.Run("SupportedSPDXVersion", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "json", "spdx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "SPDX-2.3", got.Desc)
	})

	t.Run("UnSupportedSPDXVersion", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-100.3", "json", "spdx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported version: SPDX-100.3 (spec spdx)", got.Desc)
	})

	t.Run("UnsupportedCDXVersion", func(t *testing.T) {
		doc := sbom.CdxDoc{CdxSpec: cdxSpecForStructural("9.9", "json", "cyclonedx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported version: 9.9 (spec cyclonedx)", got.Desc)
	})
}

func Test_SBOMFileFormat(t *testing.T) {
	t.Run("SupportedFormatForSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "json", "spdx")}

		got := SBOMFileFormat(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "json", got.Desc)
	})

	t.Run("UnsupportedFormatForSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "pdf", "spdx")}

		got := SBOMFileFormat(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported format: pdf (spec spdx)", got.Desc)
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		doc := sbom.CdxDoc{CdxSpec: cdxSpecForStructural("1.4", "ppl", "cyclonedx")}

		got := SBOMFileFormat(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported format: ppl (spec cyclonedx)", got.Desc)
	})
}

type spdxSchemaDoc struct {
	sbom.SpdxDoc
	valid bool
}

func (d spdxSchemaDoc) SchemaValidation() bool { return d.valid }

type cdxSchemaDoc struct {
	sbom.CdxDoc
	valid bool
}

func (d cdxSchemaDoc) SchemaValidation() bool { return d.valid }

func Test_SBOMSchemaValid(t *testing.T) {
	t.Run("ValidSchema_SPDX", func(t *testing.T) {
		doc := spdxSchemaDoc{
			SpdxDoc: sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "json", "spdx")},
			valid:   true,
		}

		got := SBOMSchemaValid(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "schema valid", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("ValidSchema_CDX", func(t *testing.T) {
		doc := cdxSchemaDoc{
			CdxDoc: sbom.CdxDoc{CdxSpec: cdxSpecForStructural("1.6", "json", "cyclonedx")},
			valid:  true,
		}

		got := SBOMSchemaValid(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "schema valid", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("InvalidSchema_SPDX", func(t *testing.T) {
		doc := spdxSchemaDoc{
			SpdxDoc: sbom.SpdxDoc{SpdxSpec: spdxSpecForStructural("SPDX-2.3", "json", "spdx")},
			valid:   false,
		}

		got := SBOMSchemaValid(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "schema invalid", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("InvalidSchema_CDX", func(t *testing.T) {
		doc := cdxSchemaDoc{
			CdxDoc: sbom.CdxDoc{CdxSpec: cdxSpecForStructural("1.4", "json", "cyclonedx")},
			valid:  false,
		}

		got := SBOMSchemaValid(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "schema invalid", got.Desc)
		assert.False(t, got.Ignore)
	})
}
