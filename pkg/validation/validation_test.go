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

package validation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate_CycloneDX(t *testing.T) {

	tests := []struct {
		name    string
		version string
		file    string
		want    bool
	}{
		// cyclonedx:1.2
		{
			name:    "cdx-1.2-min-required",
			version: "1.2",
			file:    "cdx-1-2-min-required.cdx.json",
			want:    true,
		},

		// cyclonedx:1.3
		{
			name:    "cdx-1.3-min-required",
			version: "1.3",
			file:    "cdx-1-3-min-required.cdx.json",
			want:    true,
		},
		{
			name:    "cdx-1.3-valid",
			version: "1.3",
			file:    "cdx-1-3-valid-sbom.cdx.json",
			want:    true,
		},

		// cyclonedx:1.4
		{
			name:    "cdx-1.4-min-required",
			version: "1.4",
			file:    "cdx-1-4-min-required.cdx.json",
			want:    true,
		},
		{
			name:    "cdx-1.4-valid",
			version: "1.4",
			file:    "cdx-1-4-valid-sbom.cdx.json",
			want:    true,
		},
		{
			name:    "cdx-1.4-invalid",
			version: "1.4",
			file:    "cdx-1-4-invalid-sbom.cdx.json",
			want:    false,
		},

		// CycloneDx:1.5
		{
			name:    "cdx-1.5-min-required",
			version: "1.5",
			file:    "cdx-1-5-min-required.cdx.json",
			want:    true,
		},
		{
			name:    "cdx-1.5-valid",
			version: "1.5",
			file:    "cdx-1-5-valid-sbom.cdx.json",
			want:    true,
		},

		// CycloneDx:1.6
		{
			name:    "cdx-1.6-min-required",
			version: "1.6",
			file:    "cdx-1-6-min-required.cdx.json",
			want:    true,
		},
		{
			name:    "cdx-1.6-valid",
			version: "1.6",
			file:    "cdx-1-6-valid-sbom.cdx.json",
			want:    true,
		},
		{
			name:    "cdx-1.6-invalid",
			version: "1.6",
			file:    "cdx-1-6-invalid-sbom.cdx.json",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom := loadCDXTestFile(t, tt.file)
			result := Validate("cyclonedx", tt.version, sbom)

			if result.Valid != tt.want {
				t.Fatalf(
					"unexpected validation result: got=%v want=%v errors=%v",
					result.Valid,
					tt.want,
					result.Logs,
				)
			}
		})
	}
}

func loadCDXTestFile(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "validation", "cyclonedx", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", name, err)
	}
	return data
}

func TestValidate_Miscellaneous(t *testing.T) {
	tests := []struct {
		name    string
		version string
		file    string
		want    bool
	}{
		// invalid spdx and cdx schema
		{
			name:    "spdx-no-timestamp",
			version: "2.3",
			file:    "spdx-no-timestamp.json",
			want:    false,
		},
		{
			name:    "spdx-no-authors",
			version: "2.3",
			file:    "spdx-no-authors.json",
			want:    false,
		},

		{
			name:    "cdx-with-signature-no-key",
			version: "1.5",
			file:    "cdx-with-signature-no-key.json",
			want:    false,
		},
		{
			name:    "cdx-with-incomplete-signature",
			version: "1.5",
			file:    "cdx-with-incomplete-signature.json",
			want:    false,
		},
		{
			name:    "cdx-with-complete-signature",
			version: "1.5",
			file:    "cdx-with-complete-signature.json",
			want:    false,
		},
		{
			name:    "cdx-perfect-score",
			version: "1.5",
			file:    "cdx-perfect-score.json",
			want:    false,
		},
		{
			name:    "cdx-old-version",
			version: "1.2",
			file:    "cdx-old-version.json",
			want:    false,
		},
		{
			name:    "cdx-no-dependencies",
			version: "1.5",
			file:    "cdx-no-dependencies.json",
			want:    false,
		},

		// valid spdx and cdx SBOM schema

		{
			name:    "cdx-invalid-licenses",
			version: "1.5",
			file:    "cdx-invalid-licenses.json",
			want:    true,
		},
		{
			name:    "cdx-minimal",
			version: "1.5",
			file:    "cdx-minimal.json",
			want:    true,
		},
		{
			name:    "cdx-no-authors",
			version: "1.5",
			file:    "cdx-no-authors.json",
			want:    true,
		},
		{
			name:    "cdx-no-checksums",
			version: "1.5",
			file:    "cdx-no-checksums.json",
			want:    true,
		},
		{
			name:    "cdx-no-checksums",
			version: "1.5",
			file:    "cdx-no-checksums.json",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom := loadMiscTestFile(t, tt.file)

			result := Validate("spdx", tt.version, sbom)

			if result.Valid {
				t.Fatalf(
					"expected schema validation to fail, but it passed (file=%s)",
					tt.file,
				)
			}
		})
	}
}

func loadMiscTestFile(t *testing.T, name string) []byte {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "fixtures", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", name, err)
	}
	return data
}
