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

package profiles

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/stretchr/testify/assert"
)

func spdxDocSpec(ver, fileFmt, spec string) *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = ver
	s.SpecType = spec
	s.Format = fileFmt
	s.Spdxid = "DOCUMENT"
	s.Namespace = "https://example.com/ns"
	return s
}

func cdxDocSpec(ver, fileFmt, spec string) *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = ver
	s.SpecType = spec
	s.Format = fileFmt
	s.URI = "urn:uuid:11111111-2222-3333-4444-555555555555"
	return s
}

func Test_SBOMSpec(t *testing.T) {
	t.Run("SupportedSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "spdx")}

		got := SBOMSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present spdx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("SupportedSPDXUpperCase", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "SPDX")}

		got := SBOMSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present spdx", got.Desc)
		assert.False(t, got.Ignore)
	})

	t.Run("UnsupportedSpec", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "something-else")}

		got := SBOMSpec(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Contains(t, got.Desc, "unsupported spec")
	})

	t.Run("UnsupportedSpec", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-4.3", "yaml", "something-else")}

		got := SBOMSpec(doc)
		assert.Equal(t, 0.0, got.Score)
		assert.Contains(t, got.Desc, "unsupported spec")
	})
}

func Test_SBOMSpecVersion(t *testing.T) {
	t.Run("SupportedSPDXVersion", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "spdx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present SPDX-2.3", got.Desc)
	})

	t.Run("UnSupportedSPDXVersion", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-100.3", "json", "spdx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported spec version: SPDX-100.3 (spec spdx)", got.Desc)
	})

	t.Run("UnsupportedCDXVersion", func(t *testing.T) {
		doc := sbom.CdxDoc{CdxSpec: cdxDocSpec("9.9", "json", "cyclonedx")}

		got := SBOMSpecVersion(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported spec version: 9.9 (spec cyclonedx)", got.Desc)
	})
}

func Test_SBOMFileFormat(t *testing.T) {
	t.Run("SupportedFormatForSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "json", "spdx")}

		got := SBOMAutomationSpec(doc)

		assert.Equal(t, 10.0, got.Score)
		assert.Equal(t, "present json", got.Desc)
	})

	t.Run("UnsupportedFormatForSPDX", func(t *testing.T) {
		doc := sbom.SpdxDoc{SpdxSpec: spdxDocSpec("SPDX-2.3", "pdf", "spdx")}

		got := SBOMAutomationSpec(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported file format: pdf (spec spdx)", got.Desc)
	})

	t.Run("UnsupportedFormat", func(t *testing.T) {
		doc := sbom.CdxDoc{CdxSpec: cdxDocSpec("1.4", "ppl", "cyclonedx")}

		got := SBOMAutomationSpec(doc)

		assert.Equal(t, 0.0, got.Score)
		assert.Equal(t, "unsupported file format: ppl (spec cyclonedx)", got.Desc)
	})
}

func spdxDocLifecycle(lifecycle string) *sbom.Specs {
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "SPDX"
	s.Format = "json"
	s.Spdxid = "DOCUMENT"
	s.Namespace = "https://example.com/ns"
	return s
}

// func cdxDocSpec(lifecycle string) *sbom.Specs {
// 	s := sbom.NewSpec()
// 	s.Version = "1.4"
// 	s.SpecType = "cyclonedx"
// 	s.Format = "json"
// 	s.URI = "urn:uuid:11111111-2222-3333-4444-555555555555"
// 	return s
// }
