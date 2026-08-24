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

package list_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/list"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ListTestCase represents a single list command integration test
type ListTestCase struct {
	Name            string
	SBOMFile        string
	Feature         string
	Profile         string
	Missing         bool
	ExpectedFound   int // expected number of components/items with feature present
	ExpectedMissing int // expected number of components/items missing feature
}

// TestListIntegrationForSPDX3_Generic tests generic (non-profile) features
func TestListIntegrationForSPDX3_Generic(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// ============================================================================
		// COMPONENT FIELDS - PRESENT (using spdx3-perfect-score.json)
		// ============================================================================

		// Component name - PRESENT
		{
			Name:          "Component name - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_name",
			ExpectedFound: 2,
		},

		// Component version - PRESENT
		{
			Name:          "Component version - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_version",
			ExpectedFound: 2,
		},
		// Component version - ABSENT
		{
			Name:            "Component version - ABSENT in no-version",
			SBOMFile:        filepath.Join(base, "spdx3-no-version.json"),
			Feature:         "comp_version",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component supplier - PRESENT
		{
			Name:          "Component supplier - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_supplier",
			ExpectedFound: 2,
		},
		// Component supplier - ABSENT
		{
			Name:            "Component supplier - ABSENT in no-supplier",
			SBOMFile:        filepath.Join(base, "spdx3-no-supplier.json"),
			Feature:         "comp_supplier",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component checksums - PRESENT
		{
			Name:          "Component checksums - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_checksums",
			ExpectedFound: 2,
		},
		// Component checksums - ABSENT
		{
			Name:            "Component checksums - ABSENT in no-checksum",
			SBOMFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			Feature:         "comp_checksums",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component PURL - PRESENT
		{
			Name:          "Component PURL - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_purl",
			ExpectedFound: 2,
		},
		// Component PURL - ABSENT
		{
			Name:            "Component PURL - ABSENT in no-unique-id",
			SBOMFile:        filepath.Join(base, "spdx3-no-unique-id.json"),
			Feature:         "comp_purl",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component CPE - PRESENT
		{
			Name:          "Component CPE - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_cpe",
			ExpectedFound: 2,
		},
		// Component CPE - ABSENT
		{
			Name:            "Component CPE - ABSENT in no-cpe",
			SBOMFile:        filepath.Join(base, "spdx3-no-cpe.json"),
			Feature:         "comp_cpe",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component copyright - PRESENT
		{
			Name:          "Component copyright - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_copyright",
			ExpectedFound: 2,
		},
		// Component copyright - ABSENT
		{
			Name:            "Component copyright - ABSENT in no-copyright",
			SBOMFile:        filepath.Join(base, "spdx3-no-copyright.json"),
			Feature:         "comp_copyright",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component type (primary_purpose) - PRESENT
		{
			Name:          "Component type - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_primary_purpose",
			ExpectedFound: 2,
		},
		// Component type - ABSENT
		{
			Name:            "Component type - ABSENT in no-type",
			SBOMFile:        filepath.Join(base, "spdx3-no-type.json"),
			Feature:         "comp_primary_purpose",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component unique IDs (PURL + CPE) - PRESENT
		{
			Name:          "Component unique IDs - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_uniq_ids",
			ExpectedFound: 2,
		},
		// Component unique IDs - ABSENT
		{
			Name:            "Component unique IDs - ABSENT in no-unique-id",
			SBOMFile:        filepath.Join(base, "spdx3-no-unique-id.json"),
			Feature:         "comp_uniq_ids",
			Missing:         true,
			ExpectedMissing: 2,
		},

		// Component licenses (all) - PRESENT
		{
			Name:          "Component licenses - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_licenses",
			ExpectedFound: 2,
		},

		// Component concluded license - PRESENT
		{
			Name:          "Component concluded license - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_concluded_license",
			ExpectedFound: 2,
		},

		// Component declared license - PRESENT
		{
			Name:          "Component declared license - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_declared_license",
			ExpectedFound: 2,
		},

		// Component all licenses (comp_all_licenses) - PRESENT
		{
			Name:          "Component all licenses - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_all_licenses",
			ExpectedFound: 2,
		},

		// ============================================================================
		// DOCUMENT FIELDS - PRESENT (using spdx3-perfect-score.json)
		// ============================================================================

		// Document authors - PRESENT
		{
			Name:          "Document authors - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_authors",
			ExpectedFound: 1,
		},
		// Document authors - ABSENT
		{
			Name:            "Document authors - ABSENT in no-authors",
			SBOMFile:        filepath.Join(base, "spdx3-no-authors.json"),
			Feature:         "sbom_authors",
			Missing:         true,
			ExpectedMissing: 1,
		},

		// Document timestamp - PRESENT
		{
			Name:          "Document timestamp - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_creation_timestamp",
			ExpectedFound: 1,
		},
		// Document timestamp - ABSENT
		{
			Name:            "Document timestamp - ABSENT in no-timestamp",
			SBOMFile:        filepath.Join(base, "spdx3-no-timestamp.json"),
			Feature:         "sbom_creation_timestamp",
			Missing:         true,
			ExpectedMissing: 1,
		},

		// Document tool (creator_and_version) - PRESENT
		{
			Name:          "Document tool - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_creator_and_version",
			ExpectedFound: 1,
		},
		// Document tool - ABSENT
		{
			Name:            "Document tool - ABSENT in no-tool",
			SBOMFile:        filepath.Join(base, "spdx3-no-tool.json"),
			Feature:         "sbom_creator_and_version",
			Missing:         true,
			ExpectedMissing: 1,
		},

		// Document spec version - PRESENT
		{
			Name:          "Document spec version - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_spec_version",
			ExpectedFound: 1,
		},

		// Document spec - PRESENT
		{
			Name:          "Document spec - PRESENT (spdx)",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_spec",
			ExpectedFound: 1,
		},

		// Document spec file format - PRESENT
		{
			Name:          "Document spec file format - PRESENT (json)",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_spec_file_format",
			ExpectedFound: 1,
		},

		// Document URI (namespace) - PRESENT
		{
			Name:          "Document URI - PRESENT in perfect score",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_uri",
			ExpectedFound: 1,
		},

		// Document dependencies - PRESENT
		{
			Name:          "Document dependencies - PRESENT in with-dependencies",
			SBOMFile:      filepath.Join(base, "spdx3-with-dependencies.json"),
			Feature:       "sbom_dependencies",
			ExpectedFound: 1,
		},
		// Document dependencies - ABSENT
		{
			Name:            "Document dependencies - ABSENT in no-dependencies",
			SBOMFile:        filepath.Join(base, "spdx3-no-dependencies.json"),
			Feature:         "sbom_dependencies",
			Missing:         true,
			ExpectedMissing: 1,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForSPDX3_NTIA tests NTIA profile features
func TestListIntegrationForSPDX3_NTIA(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// NTIA profile - Component fields
		{
			Name:          "NTIA profile - comp_name PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_name",
			Profile:       "ntia",
			ExpectedFound: 2,
		},
		{
			Name:          "NTIA profile - comp_supplier PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_supplier",
			Profile:       "ntia",
			ExpectedFound: 2,
		},
		{
			Name:          "NTIA profile - comp_uniq_id PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_uniq_id",
			Profile:       "ntia",
			ExpectedFound: 2,
		},
		// NTIA profile - Document fields
		{
			Name:          "NTIA profile - sbom_authors PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_authors",
			Profile:       "ntia",
			ExpectedFound: 1,
		},
		{
			Name:          "NTIA profile - sbom_timestamp PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_timestamp",
			Profile:       "ntia",
			ExpectedFound: 1,
		},
		// NTIA profile - ABSENT cases
		{
			Name:            "NTIA profile - comp_supplier ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-supplier.json"),
			Feature:         "comp_supplier",
			Profile:         "ntia",
			Missing:         true,
			ExpectedMissing: 2,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForSPDX3_BSIv21 tests BSI v2.1 profile features
func TestListIntegrationForSPDX3_BSIv21(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// BSI v2.1 profile - Component fields
		{
			Name:          "BSI v2.1 profile - comp_name PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_name",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_version",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_deployable_hash PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-deployable-hash.json"),
			Feature:       "comp_deployable_hash",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_source_code_url PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_source_code_url",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_source_code_url via source artifact",
			SBOMFile:      filepath.Join(base, "spdx3-with-source-artifact-source-code.json"),
			Feature:       "comp_source_code_url",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_executable_prop PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-executable-prop.json"),
			Feature:       "comp_executable_prop",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:            "BSI v2.1 profile - comp_executable_prop ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			Feature:         "comp_executable_prop",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_archive_prop PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-archive-prop.json"),
			Feature:       "comp_archive_prop",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:            "BSI v2.1 profile - comp_archive_prop ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			Feature:         "comp_archive_prop",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_structured_prop PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-structured-prop.json"),
			Feature:       "comp_structured_prop",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:            "BSI v2.1 profile - comp_structured_prop ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			Feature:         "comp_structured_prop",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_download_url PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_download_url",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_download_url via binary artifact",
			SBOMFile:      filepath.Join(base, "spdx3-with-binary-artifact-download.json"),
			Feature:       "comp_download_url",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		// BSI v2.1 profile - Document fields
		{
			Name:          "BSI v2.1 profile - comp_original_licenses PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_original_licenses",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:            "BSI v2.1 profile - comp_original_licenses ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-original-license.json"),
			Feature:         "comp_original_licenses",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_effective_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-effective-license.json"),
			Feature:       "comp_effective_license",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:            "BSI v2.1 profile - comp_effective_license ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-original-license.json"),
			Feature:         "comp_effective_license",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_source_hash PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-source-code-hash.json"),
			Feature:       "comp_source_hash",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:            "BSI v2.1 profile - comp_source_hash ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:         "comp_source_hash",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:          "BSI v2.1 profile - comp_security_txt_url PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-security-txt.json"),
			Feature:       "comp_security_txt_url",
			Profile:       "bsiv21",
			ExpectedFound: 2,
		},
		{
			Name:            "BSI v2.1 profile - comp_security_txt_url ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:         "comp_security_txt_url",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:          "BSI v2.1 profile - sbom_creator PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_creator",
			Profile:       "bsiv21",
			ExpectedFound: 1,
		},
		{
			Name:          "BSI v2.1 profile - sbom_timestamp PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_timestamp",
			Profile:       "bsiv21",
			ExpectedFound: 1,
		},
		// BSI v2.1 profile - ABSENT cases
		{
			Name:            "BSI v2.1 profile - sbom_timestamp ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-timestamp.json"),
			Feature:         "sbom_timestamp",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 1,
		},
		{
			Name:          "BSI v2.1 profile - sbom_bomlinks PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-bom-links.json"),
			Feature:       "sbom_bomlinks",
			Profile:       "bsiv21",
			ExpectedFound: 1,
		},
		{
			Name:            "BSI v2.1 profile - sbom_bomlinks ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:         "sbom_bomlinks",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 1,
		},
		{
			Name:            "BSI v2.1 profile - comp_deployable_hash ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			Feature:         "comp_deployable_hash",
			Profile:         "bsiv21",
			Missing:         true,
			ExpectedMissing: 2,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForSPDX3_BSIv11 tests BSI v1.1 profile features
func TestListIntegrationForSPDX3_BSIv11(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// BSI v1.1 profile - Document fields
		{
			Name:          "BSI v1.1 profile - sbom_creator PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_creator",
			Profile:       "bsiv11",
			ExpectedFound: 1,
		},
		{
			Name:          "BSI v1.1 profile - sbom_timestamp PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_timestamp",
			Profile:       "bsiv11",
			ExpectedFound: 1,
		},
		{
			Name:          "BSI v1.1 profile - sbom_uri PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_uri",
			Profile:       "bsiv11",
			ExpectedFound: 1,
		},
		// BSI v1.1 profile - Component fields
		{
			Name:          "BSI v1.1 profile - comp_creator PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_creator",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_name PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_name",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_version",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_depth PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-dependencies.json"),
			Feature:       "comp_depth",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_license",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_hash PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-deployable-hash.json"),
			Feature:       "comp_hash",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_unique_identifiers PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_unique_identifiers",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_source_url PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_source_url",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v1.1 profile - comp_executable_url PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_executable_url",
			Profile:       "bsiv11",
			ExpectedFound: 2,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForSPDX3_BSIv20 tests BSI v2.0 profile features
func TestListIntegrationForSPDX3_BSIv20(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// BSI v2.0 profile - Document fields
		{
			Name:          "BSI v2.0 profile - sbom_creator PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_creator",
			Profile:       "bsiv20",
			ExpectedFound: 1,
		},
		{
			Name:          "BSI v2.0 profile - sbom_timestamp PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_timestamp",
			Profile:       "bsiv20",
			ExpectedFound: 1,
		},
		{
			Name:          "BSI v2.0 profile - sbom_uri PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_uri",
			Profile:       "bsiv20",
			ExpectedFound: 1,
		},
		// BSI v2.0 profile - Component fields
		{
			Name:          "BSI v2.0 profile - comp_creator PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_creator",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_name PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_name",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_version",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_depth PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-dependencies.json"),
			Feature:       "comp_depth",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_associated_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_associated_license",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_deployable_hash PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-deployable-hash.json"),
			Feature:       "comp_deployable_hash",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_source_code_url PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_source_code_url",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_executable_property PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-executable-prop.json"),
			Feature:       "comp_executable_property",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_download_url PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_download_url",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_other_identifiers PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_other_identifiers",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_concluded_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-declared-concluded-licenses.json"),
			Feature:       "comp_concluded_license",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
		{
			Name:          "BSI v2.0 profile - comp_declared_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-declared-concluded-licenses.json"),
			Feature:       "comp_declared_license",
			Profile:       "bsiv20",
			ExpectedFound: 2,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForSPDX3_FSCT tests FSCT profile features
func TestListIntegrationForSPDX3_FSCT(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// FSCT profile - Document fields
		{
			Name:          "FSCT profile - sbom_provenance PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_provenance",
			Profile:       "fsct",
			ExpectedFound: 1,
		},
		{
			Name:          "FSCT profile - sbom_primary_component PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_primary_component",
			Profile:       "fsct",
			ExpectedFound: 1,
		},
		// FSCT profile - Component fields
		{
			Name:          "FSCT profile - comp_identity PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_identity",
			Profile:       "fsct",
			ExpectedFound: 2,
		},
		{
			Name:          "FSCT profile - supplier_attribution PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "supplier_attribution",
			Profile:       "fsct",
			ExpectedFound: 2,
		},
		{
			Name:          "FSCT profile - comp_unique_id PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_unique_id",
			Profile:       "fsct",
			ExpectedFound: 2,
		},
		{
			Name:          "FSCT profile - artifact_integrity PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "artifact_integrity",
			Profile:       "fsct",
			ExpectedFound: 2,
		},
		{
			Name:          "FSCT profile - license_coverage PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "license_coverage",
			Profile:       "fsct",
			ExpectedFound: 2,
		},
		{
			Name:          "FSCT profile - copyright_coverage PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "copyright_coverage",
			Profile:       "fsct",
			ExpectedFound: 2,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForSPDX3_Interlynk tests Interlynk profile features
func TestListIntegrationForSPDX3_Interlynk(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// Interlynk profile - Document fields
		{
			Name:          "Interlynk profile - sbom_timestamp PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_timestamp",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_authors PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_authors",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_tool PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_tool",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_namespace PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_namespace",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_primary_component PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_primary_component",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_data_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_data_license",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_spec_declared PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_spec_declared",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_spec_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_spec_version",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_file_format PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_file_format",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		// Interlynk profile - Component fields
		{
			Name:          "Interlynk profile - comp_name PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_name",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_version",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_local_id PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_local_id",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_checksums PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_checksums",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_sha256 PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_sha256",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_source_code PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_source_code",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_supplier PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_supplier",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_purpose PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_purpose",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_licenses PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_licenses",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_valid_licenses PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_valid_licenses",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_spdx_listed_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_spdx_listed_license",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_no_deprecated_licenses PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_no_deprecated_licenses",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_no_restrictive_licenses PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_no_restrictive_licenses",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_declared_licenses PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_declared_licenses",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_purl PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_purl",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		{
			Name:          "Interlynk profile - comp_cpe PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_cpe",
			Profile:       "interlynk",
			ExpectedFound: 2,
		},
		// Interlynk profile - Document fields missing from perfect-score fixture
		{
			Name:          "Interlynk profile - sbom_lifecycle PRESENT",
			SBOMFile:      filepath.Join("..", "..", "testdata", "bsi", "spdx3", "v2.1.0-complete-all-fields.json"),
			Feature:       "sbom_lifecycle",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:          "Interlynk profile - sbom_completeness PRESENT",
			SBOMFile:      filepath.Join("..", "..", "testdata", "bsi", "spdx3", "v2.1.0-complete-all-fields.json"),
			Feature:       "sbom_completeness",
			Profile:       "interlynk",
			ExpectedFound: 1,
		},
		{
			Name:            "Interlynk profile - sbom_signature MISSING in spdx3",
			SBOMFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:         "sbom_signature",
			Profile:         "interlynk",
			Missing:         true,
			ExpectedMissing: 1,
		},
		{
			Name:            "Interlynk profile - sbom_lifecycle MISSING in spdx3",
			SBOMFile:        filepath.Join(base, "spdx3-no-version.json"),
			Feature:         "sbom_lifecycle",
			Profile:         "interlynk",
			Missing:         true,
			ExpectedMissing: 1,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForSPDX3_CISA2026 tests CISA 2026 profile features
func TestListIntegrationForSPDX3_CISA2026(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// CISA 2026 profile - Document fields (PRESENT)
		{
			Name:          "CISA 2026 profile - sbom_data_format PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_data_format",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
		{
			Name:          "CISA 2026 profile - sbom_spec_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_spec_version",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
		{
			Name:          "CISA 2026 profile - sbom_author PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_author",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
		{
			Name:          "CISA 2026 profile - sbom_tool_name PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_tool_name",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
		{
			Name:          "CISA 2026 profile - sbom_tool_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_tool_version",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
		{
			Name:          "CISA 2026 profile - sbom_timestamp PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "sbom_timestamp",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
		{
			Name:          "CISA 2026 profile - sbom_relationships PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-with-dependencies.json"),
			Feature:       "sbom_relationships",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
		// CISA 2026 profile - Document fields (ABSENT)
		{
			Name:            "CISA 2026 profile - sbom_author ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-authors.json"),
			Feature:         "sbom_author",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 1,
		},
		{
			Name:            "CISA 2026 profile - sbom_timestamp ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-timestamp.json"),
			Feature:         "sbom_timestamp",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 1,
		},
		{
			Name:            "CISA 2026 profile - sbom_relationships ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-dependencies.json"),
			Feature:         "sbom_relationships",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 1,
		},
		// CISA 2026 profile - Component fields (PRESENT)
		{
			Name:          "CISA 2026 profile - comp_name PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_name",
			Profile:       "cisa-2026",
			ExpectedFound: 2,
		},
		{
			Name:          "CISA 2026 profile - comp_version PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_version",
			Profile:       "cisa-2026",
			ExpectedFound: 2,
		},
		{
			Name:          "CISA 2026 profile - comp_uniq_id PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_uniq_id",
			Profile:       "cisa-2026",
			ExpectedFound: 2,
		},
		{
			Name:          "CISA 2026 profile - comp_producer PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_producer",
			Profile:       "cisa-2026",
			ExpectedFound: 2,
		},
		{
			Name:          "CISA 2026 profile - comp_hash_value PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_hash_value",
			Profile:       "cisa-2026",
			ExpectedFound: 2,
		},
		{
			Name:          "CISA 2026 profile - comp_hash_algo PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_hash_algo",
			Profile:       "cisa-2026",
			ExpectedFound: 2,
		},
		{
			Name:          "CISA 2026 profile - comp_license PRESENT",
			SBOMFile:      filepath.Join(base, "spdx3-perfect-score.json"),
			Feature:       "comp_license",
			Profile:       "cisa-2026",
			ExpectedFound: 2,
		},
		// CISA 2026 profile - Component fields (ABSENT)
		{
			Name:            "CISA 2026 profile - comp_version ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-version.json"),
			Feature:         "comp_version",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:            "CISA 2026 profile - comp_uniq_id ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-unique-id.json"),
			Feature:         "comp_uniq_id",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:            "CISA 2026 profile - comp_producer ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-supplier.json"),
			Feature:         "comp_producer",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:            "CISA 2026 profile - comp_hash_value ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			Feature:         "comp_hash_value",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:            "CISA 2026 profile - comp_hash_algo ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			Feature:         "comp_hash_algo",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 2,
		},
		{
			Name:            "CISA 2026 profile - comp_license ABSENT",
			SBOMFile:        filepath.Join(base, "spdx3-no-original-license.json"),
			Feature:         "comp_license",
			Profile:         "cisa-2026",
			Missing:         true,
			ExpectedMissing: 2,
		},
		// Component producer - supplier email only
		{
			Name:          "CISA 2026 profile - comp_producer via supplier email only",
			SBOMFile:      filepath.Join(base, "spdx3-with-comp-supplier-email-only.json"),
			Feature:         "comp_producer",
			Profile:         "cisa-2026",
			ExpectedFound: 1,
		},
		// Component producer - supplier URL only
		{
			Name:          "CISA 2026 profile - comp_producer via supplier URL only",
			SBOMFile:      filepath.Join(base, "spdx3-with-comp-supplier-url-only.json"),
			Feature:         "comp_producer",
			Profile:         "cisa-2026",
			ExpectedFound: 1,
		},
		// Component producer - manufacturer name only
		{
			Name:          "CISA 2026 profile - comp_producer via manufacturer name only",
			SBOMFile:      filepath.Join(base, "spdx3-with-comp-manufacturer-name-only.json"),
			Feature:         "comp_producer",
			Profile:         "cisa-2026",
			ExpectedFound: 1,
		},
		// Component producer - manufacturer email only
		{
			Name:          "CISA 2026 profile - comp_producer via manufacturer email only",
			SBOMFile:      filepath.Join(base, "spdx3-with-comp-manufacturer-email-only.json"),
			Feature:         "comp_producer",
			Profile:         "cisa-2026",
			ExpectedFound: 1,
		},
		// Component producer - manufacturer URL only
		{
			Name:          "CISA 2026 profile - comp_producer via manufacturer URL only",
			SBOMFile:      filepath.Join(base, "spdx3-with-comp-manufacturer-url-only.json"),
			Feature:         "comp_producer",
			Profile:         "cisa-2026",
			ExpectedFound: 1,
		},
	}

	runListTestCases(t, testCases)
}

// TestListIntegrationForCDX_CISA2026 tests CISA 2026 profile features with CycloneDX fixtures
func TestListIntegrationForCDX_CISA2026(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []ListTestCase{
		// Component producer - author email only (CycloneDX component-level authors)
		{
			Name:          "CISA 2026 profile - CDX comp_producer via author email only",
			SBOMFile:      filepath.Join(base, "cdx-with-comp-author-email-only.json"),
			Feature:       "comp_producer",
			Profile:       "cisa-2026",
			ExpectedFound: 1,
		},
	}

	runListTestCases(t, testCases)
}

// runListTestCases executes a slice of ListTestCases
func runListTestCases(t *testing.T, testCases []ListTestCase) {
	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.Name, func(t *testing.T) {
			// Check file exists
			if _, err := os.Stat(tc.SBOMFile); os.IsNotExist(err) {
				t.Fatalf("SBOM file not found: %s", tc.SBOMFile)
			}

			// Build list params
			params := &list.Params{
				Path:     []string{tc.SBOMFile},
				Features: []string{tc.Feature},
				Profile:  tc.Profile,
				Missing:  tc.Missing,
			}

			// Run list command
			ctx := context.Background()
			result, err := list.ComponentsListResult(ctx, params)
			require.NoError(t, err, "List command failed for feature: %s", tc.Feature)
			require.NotNil(t, result, "Result should not be nil")

			// Verify results
			if result.IsComponentFeature {
				// Component-level feature
				if tc.Missing {
					assert.Equal(t, tc.ExpectedMissing, len(result.Components), "Unexpected missing count for feature: %s", tc.Feature)
				} else {
					assert.Equal(t, tc.ExpectedFound, len(result.Components), "Unexpected found count for feature: %s", tc.Feature)
				}
			} else {
				// Document-level feature
				if tc.Missing {
					// When --missing is used, Present should be false
					assert.False(t, result.DocumentProperty.Present, "Document property should be missing for feature: %s", tc.Feature)
				} else {
					// Normal mode
					assert.True(t, result.DocumentProperty.Present, "Document property should be present for feature: %s", tc.Feature)
				}
			}
		})
	}
}
