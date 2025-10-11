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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
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

func TestCompWithSHA1Plus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_ = ctx

	tests := []struct {
		name     string
		doc      sbom.Document
		want     config.FeatureScore
		wantDesc string
	}{
		{
			name: "no components → N/A",
			doc:  makeSPDXDocForIntegrity(),
			want: config.FeatureScore{Score: 0, Ignore: true},
		},
		{
			name: "all have SHA-1 or stronger",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-1", "a")},
				[]sbom.GetChecksum{ch("SHA-256", "b")},
				[]sbom.GetChecksum{ch("SHA-512", "c")},
			),
			// 3/3 → 10.0
			want: config.FeatureScore{Score: 10, Ignore: false},
		},
		{
			name: "partial coverage",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("MD5", "x")},         // not SHA1+
				[]sbom.GetChecksum{ch("SHA-1", "y")},       // yes
				[]sbom.GetChecksum{ch("unknown", "z")},     // not
				[]sbom.GetChecksum{ch("SHA-384", "w")},     // yes
				[]sbom.GetChecksum{},                       // not
				[]sbom.GetChecksum{ch("sha-256", "lower")}, // yes (case normalization handled by extractor impl)
			),
			// 3/6 → 5.0
			want: config.FeatureScore{Score: 5, Ignore: false},
		},
		{
			name: "none",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("MD5", "x")},
				[]sbom.GetChecksum{ch("CRC32", "y")},
			),
			want: config.FeatureScore{Score: 0, Ignore: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CompWithSHA1Plus(tc.doc)
			assert.InDelta(t, tc.want.Score, got.Score, 0.001)
			assert.Equal(t, tc.want.Ignore, got.Ignore)
			assert.NotEmpty(t, got.Desc)
		})
	}
}

func TestCompWithSHA256Plus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_ = ctx

	tests := []struct {
		name     string
		doc      sbom.Document
		want     config.FeatureScore
		wantDesc string
	}{
		{
			name: "no components → N/A",
			doc:  makeSPDXDocForIntegrity(),
			want: config.FeatureScore{Score: 0, Ignore: true},
		},
		{
			name: "all have SHA-256 or stronger",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-256", "a")},
				[]sbom.GetChecksum{ch("SHA-384", "b")},
				[]sbom.GetChecksum{ch("SHA-512", "c")},
			),
			// 3/3 → 10.0
			want: config.FeatureScore{Score: 10, Ignore: false},
		},
		{
			name: "mixed: SHA-1 should not count",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("SHA-1", "old")},   // not strong enough
				[]sbom.GetChecksum{ch("SHA-256", "ok")},  // yes
				[]sbom.GetChecksum{ch("MD5", "no")},      // no
				[]sbom.GetChecksum{ch("SHA-512", "ok2")}, // yes
			),
			// 2/4 → 5.0
			want: config.FeatureScore{Score: 5, Ignore: false},
		},
		{
			name: "none",
			doc: makeSPDXDocForIntegrity(
				[]sbom.GetChecksum{ch("MD5", "x")},
				[]sbom.GetChecksum{ch("sha-1", "y")},
			),
			want: config.FeatureScore{Score: 0, Ignore: false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CompWithSHA256Plus(tc.doc)
			assert.InDelta(t, tc.want.Score, got.Score, 0.001)
			assert.Equal(t, tc.want.Ignore, got.Ignore)
			assert.NotEmpty(t, got.Desc)
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
		assert.Contains(t, fs.Desc, "succeed") // “signature verification succeeded”
	})

	t.Run("unreadable public key -> 5", func(t *testing.T) {
		fs := SBOMSignature(docUnreadableKey())
		assert.Equal(t, 5.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "cannot read public key")
	})

	t.Run("incomplete bundle -> 0", func(t *testing.T) {
		fs := SBOMSignature(docIncompleteBundle())
		assert.Equal(t, 0.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "incomplete")
	})

	t.Run("mismatched bundle -> verify fail -> 5", func(t *testing.T) {
		fs := SBOMSignature(docMismatchedBundle())
		assert.Equal(t, 5.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "present") // “present but verification failed/invalid”
	})

	t.Run("no signature -> 0", func(t *testing.T) {
		fs := SBOMSignature(docNoSignature())
		assert.Equal(t, 0.0, fs.Score)
		assert.False(t, fs.Ignore)
		assert.Contains(t, fs.Desc, "signature") // “missing signature”
	})
}
