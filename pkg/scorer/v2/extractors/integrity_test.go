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
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/stretchr/testify/assert"
)

func makeSPDXDocForIntegrity(csPerComp ...[]sbom.GetChecksum) sbom.Document {
	// Minimal SPDX spec
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.Spdxid = "DOCUMENT"
	s.CreationTimestamp = "2025-01-01T00:00:00Z"
	s.Namespace = "https://example.com/ns"

	comps := make([]sbom.GetComponent, 0, len(csPerComp))
	for i, cs := range csPerComp {
		c := sbom.NewComponent()
		c.Name = "pkg" // not important here
		c.ID = "SPDXRef-Pkg-" + string(rune('A'+i))
		c.Version = "1.0.0"
		c.Checksums = cs
		comps = append(comps, c)
	}

	return sbom.SpdxDoc{
		SpdxSpec: s,
		Comps:    comps,
	}
}

func ch(algo, content string) sbom.GetChecksum {
	return sbom.Checksum{Alg: algo, Content: content}
}

func TestCompWithStrongChecksums(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_ = ctx

	tests := []struct {
		name     string
		doc      sbom.Document
		want     catalog.ComprFeatScore
		wantDesc string
	}{
		{
			name: "no components → N/A",
			doc:  makeSPDXDocForIntegrity(),
			want: catalog.ComprFeatScore{Score: 0, Ignore: true},
		},
		{
			name: "all have strong checksums",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-256", "a")},
				[]sbom.GetChecksum{ch("SHA-384", "b")},
				[]sbom.GetChecksum{ch("SHA-512", "c")},
			),
			// 3/3 → 10.0
			want: catalog.ComprFeatScore{Score: 10, Ignore: false},
		},
		{
			name: "mixed: SHA-1 is weak, should not count",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-1", "old")},   // weak
				[]sbom.GetChecksum{ch("SHA-256", "ok")},  // strong
				[]sbom.GetChecksum{ch("MD5", "no")},      // weak
				[]sbom.GetChecksum{ch("SHA-512", "ok2")}, // strong
			),
			// 2/4 → 5.0
			want: catalog.ComprFeatScore{Score: 5, Ignore: false},
		},
		{
			name: "component with both weak and strong counts as strong",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("MD5", "x"), ch("SHA-256", "y")}, // has strong
				[]sbom.GetChecksum{ch("SHA-1", "a")},                   // weak only
			),
			// 1/2 → 5.0
			want: catalog.ComprFeatScore{Score: 5, Ignore: false},
		},
		{
			name: "none have strong",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("MD5", "x")},
				[]sbom.GetChecksum{ch("sha-1", "y")},
			),
			want: catalog.ComprFeatScore{Score: 0, Ignore: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CompWithStrongChecksums(tc.doc)
			assert.InDelta(t, tc.want.Score, got.Score, 0.001)
			assert.Equal(t, tc.want.Ignore, got.Ignore)
			assert.NotEmpty(t, got.Desc)
		})
	}
}

func TestCompWithWeakChecksums(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_ = ctx

	tests := []struct {
		name     string
		doc      sbom.Document
		want     catalog.ComprFeatScore
		wantDesc string
	}{
		{
			name: "no components → N/A",
			doc:  makeSPDXDocForIntegrity(),
			want: catalog.ComprFeatScore{Score: 0, Ignore: true},
		},
		{
			name: "no checksums at all → score 0",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{},
				[]sbom.GetChecksum{},
			),
			want: catalog.ComprFeatScore{Score: 0, Ignore: false, Desc: "no checksums found"},
		},
		{
			name: "all have strong → complete (no weak-only)",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-256", "a")},
				[]sbom.GetChecksum{ch("SHA-384", "b")},
			),
			// 2 with checksums, 0 weak-only → 2/2 → 10.0
			want: catalog.ComprFeatScore{Score: 10, Ignore: false},
		},
		{
			name: "all have weak only → need upgrade",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-1", "a")},
				[]sbom.GetChecksum{ch("MD5", "b")},
			),
			// 2 with checksums, 2 weak-only → 0/2 → 0.0
			want: catalog.ComprFeatScore{Score: 0, Ignore: false},
		},
		{
			name: "mixed: some weak-only, some strong",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-1", "weak")},  // weak-only
				[]sbom.GetChecksum{ch("SHA-256", "ok")},  // strong
				[]sbom.GetChecksum{ch("MD5", "weak2")},   // weak-only
				[]sbom.GetChecksum{ch("SHA-512", "ok2")}, // strong
			),
			// 4 with checksums, 2 weak-only → 2/4 → 5.0
			want: catalog.ComprFeatScore{Score: 5, Ignore: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CompWithWeakChecksums(tc.doc)
			assert.InDelta(t, tc.want.Score, got.Score, 0.001)
			assert.Equal(t, tc.want.Ignore, got.Ignore)
			if tc.want.Desc != "" {
				assert.Equal(t, tc.want.Desc, got.Desc)
			} else {
				assert.NotEmpty(t, got.Desc)
			}
		})
	}
}

// resolve testdata paths relative to this test file
func td(parts ...string) string {
	all := append([]string{"..", "..", "..", "..", "samples", "signature-test-data"}, parts...)
	return filepath.Join(all...)
}

// Build docs for each case using your real sample bundle.
func docValidBundle() sbom.Document {
	return sbom.SpdxDoc{
		SignatureDetail: &sbom.Signature{
			SigValue:  td("sbom.sig"),
			PublicKey: td("public_key.pem"),
			Blob:      td("SPDXJSONExample-v2.3.spdx.json"),
		},
	}
}

func docUnreadableKey() sbom.Document {
	// Non-existent key path -> cannot read -> score 5
	return sbom.SpdxDoc{
		SignatureDetail: &sbom.Signature{
			SigValue:  td("sbom.sig"),
			PublicKey: td("no_such_key.pem"),
			Blob:      td("SPDXJSONExample-v2.3.spdx.json"),
		},
	}
}

func docIncompleteBundle() sbom.Document {
	// Missing signature value -> incomplete -> score 0
	return sbom.SpdxDoc{
		SignatureDetail: &sbom.Signature{
			SigValue:  "",
			PublicKey: td("public_key.pem"),
			Blob:      td("SPDXJSONExample-v2.3.spdx.json"),
		},
	}
}

func docMismatchedBundle() sbom.Document {
	// Intentionally swap files to make verify fail -> score 5
	// (e.g., use public key path as blob; or point blob to a wrong file)
	return sbom.SpdxDoc{
		SignatureDetail: &sbom.Signature{
			SigValue:  td("sbom.sig"),
			PublicKey: td("public_key.pem"),
			Blob:      td("public_key.pem"), // wrong blob on purpose
		},
	}
}

func docNoSignature() sbom.Document {
	// Nil signature bundle -> score 0
	return sbom.SpdxDoc{ /* no Sig */ }
}

func TestSBOMSignature_VerificationMatrix(t *testing.T) {
	t.Run("valid bundle -> verify ok -> 10", func(t *testing.T) {
		fs := SBOMSignature(docValidBundle())
		assert.Equal(t, 10.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "complete") // "signature verification succeeded"
	})

	t.Run("unreadable public key -> 5", func(t *testing.T) {
		fs := SBOMSignature(docUnreadableKey())
		assert.Equal(t, 5.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "add signature")
	})

	t.Run("incomplete bundle -> 0", func(t *testing.T) {
		fs := SBOMSignature(docIncompleteBundle())
		assert.Equal(t, 0.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "add signature")
	})

	t.Run("mismatched bundle -> verify fail -> 5", func(t *testing.T) {
		fs := SBOMSignature(docMismatchedBundle())
		assert.Equal(t, 5.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "add signature") // "present but verification failed/invalid"
	})

	t.Run("no signature -> 0", func(t *testing.T) {
		fs := SBOMSignature(docNoSignature())
		assert.Equal(t, 0.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "signature") // "add signature"
	})
}
