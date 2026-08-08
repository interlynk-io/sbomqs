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

package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/policy"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PolicyTestCase represents a single policy integration test
type PolicyTestCase struct {
	Name               string
	SBOMFile           string
	PolicyFile         string
	ExpectedPass       bool   // true = all policies pass, false = at least one fails
	ExpectedViolations int    // expected number of violations (for fail cases)
	CheckField         string // specific field to verify was checked
	CheckLevel         string // "sbom" or "comp"
}

func TestPolicyIntegrationForStaticSBOMFiles(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")
	policyBase := filepath.Join("..", "..", "testdata", "policy")

	testCases := []PolicyTestCase{
		// Document-level metadata tests - PASS cases (perfect score has all fields)
		{
			Name:         "Document authors required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-doc-authors-required.yaml"),
			ExpectedPass: true,
			CheckField:   "sbom_authors",
			CheckLevel:   "doc",
		},
		{
			Name:         "Document tool required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-doc-tool-required.yaml"),
			ExpectedPass: true,
			CheckField:   "sbom_tool",
			CheckLevel:   "doc",
		},
		{
			Name:         "Document timestamp required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-doc-timestamp-required.yaml"),
			ExpectedPass: true,
			CheckField:   "sbom_timestamp",
			CheckLevel:   "doc",
		},

		// Document-level metadata tests - FAIL cases (missing fields)
		{
			Name:               "Document authors required - no-authors fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-authors.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-doc-authors-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 1,
			CheckField:         "sbom_authors",
			CheckLevel:         "doc",
		},
		{
			Name:               "Document tool required - no-tool fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-tool.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-doc-tool-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 1,
			CheckField:         "sbom_tool",
			CheckLevel:         "doc",
		},
		{
			Name:               "Document timestamp required - no-timestamp fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-timestamp.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-doc-timestamp-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 1,
			CheckField:         "sbom_timestamp",
			CheckLevel:         "doc",
		},

		// Component-level tests - PASS cases
		{
			Name:         "Component name required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-name-required.yaml"),
			ExpectedPass: true,
			CheckField:   "name",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component version required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-version-required.yaml"),
			ExpectedPass: true,
			CheckField:   "version",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component supplier required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-supplier-required.yaml"),
			ExpectedPass: true,
			CheckField:   "supplier",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component license required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-license-required.yaml"),
			ExpectedPass: true,
			CheckField:   "license",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component checksum required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-checksum-required.yaml"),
			ExpectedPass: true,
			CheckField:   "checksum",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component PURL required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-purl-required.yaml"),
			ExpectedPass: true,
			CheckField:   "purl",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component CPE required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-cpe-required.yaml"),
			ExpectedPass: true,
			CheckField:   "cpe",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component copyright required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-copyright-required.yaml"),
			ExpectedPass: true,
			CheckField:   "copyright",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component download location required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-downloadlocation-required.yaml"),
			ExpectedPass: true,
			CheckField:   "downloadlocation",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component type required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-type-required.yaml"),
			ExpectedPass: true,
			CheckField:   "type",
			CheckLevel:   "comp",
		},

		// Component-level tests - FAIL cases
		{
			Name:               "Component version required - no-version fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-version.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-version-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without version
			CheckField:         "version",
			CheckLevel:         "comp",
		},
		{
			Name:               "Component supplier required - no-supplier fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-supplier.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-supplier-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without supplier
			CheckField:         "supplier",
			CheckLevel:         "comp",
		},
		{
			Name:               "Component PURL required - no-unique-id fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-unique-id.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-purl-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without PURL
			CheckField:         "purl",
			CheckLevel:         "comp",
		},

		// Additional Component-level FAIL cases
		{
			Name:               "Component CPE required - no-cpe fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-cpe.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-cpe-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without CPE
			CheckField:         "cpe",
			CheckLevel:         "comp",
		},
		{
			Name:               "Component copyright required - no-copyright fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-copyright.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-copyright-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without copyright
			CheckField:         "copyright",
			CheckLevel:         "comp",
		},
		{
			Name:               "Component checksum required - no-checksum fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-checksum.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-checksum-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without checksum
			CheckField:         "checksum",
			CheckLevel:         "comp",
		},
		{
			Name:               "Component download location required - no-downloadlocation fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-downloadlocation.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-downloadlocation-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without download location
			CheckField:         "downloadlocation",
			CheckLevel:         "comp",
		},
		{
			Name:               "Component type required - no-type fails",
			SBOMFile:           filepath.Join(base, "spdx3-no-type.json"),
			PolicyFile:         filepath.Join(policyBase, "policy-comp-type-required.yaml"),
			ExpectedPass:       false,
			ExpectedViolations: 2, // 2 components without type
			CheckField:         "type",
			CheckLevel:         "comp",
		},

		// Declared and Concluded License tests
		{
			Name:         "Component declared license required - present passes",
			SBOMFile:     filepath.Join(base, "spdx3-with-declared-concluded-licenses.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-declared-license-required.yaml"),
			ExpectedPass: true,
			CheckField:   "declared_license",
			CheckLevel:   "comp",
		},
		{
			Name:         "Component concluded license required - present passes",
			SBOMFile:     filepath.Join(base, "spdx3-with-declared-concluded-licenses.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-concluded-license-required.yaml"),
			ExpectedPass: true,
			CheckField:   "concluded_license",
			CheckLevel:   "comp",
		},

		// Whitelist tests
		{
			Name:         "PURL whitelist - npm format passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-purl-whitelist.yaml"),
			ExpectedPass: true,
			CheckField:   "purl",
			CheckLevel:   "comp",
		},

		// Blacklist tests
		{
			Name:         "License blacklist - MIT license passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-comp-license-blacklist.yaml"),
			ExpectedPass: true,
			CheckField:   "license",
			CheckLevel:   "comp",
		},

		// Multi-field required tests (using comprehensive policies)
		{
			Name:         "Test complete component fields required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-complete-component-fields-required.yaml"),
			ExpectedPass: true,
			CheckLevel:   "comp",
		},
		{
			Name:         "Test complete document fields required - perfect score passes",
			SBOMFile:     filepath.Join(base, "spdx3-perfect-score.json"),
			PolicyFile:   filepath.Join(policyBase, "policy-complete-document-fields-required.yaml"),
			ExpectedPass: true,
			CheckLevel:   "doc",
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.Name, func(t *testing.T) {
			// Check files exist
			if _, err := os.Stat(tc.SBOMFile); os.IsNotExist(err) {
				t.Fatalf("SBOM file not found: %s", tc.SBOMFile)
			}
			if _, err := os.Stat(tc.PolicyFile); os.IsNotExist(err) {
				t.Fatalf("Policy file not found: %s", tc.PolicyFile)
			}

			// Load SBOM
			file, err := os.Open(tc.SBOMFile)
			require.NoError(t, err)
			defer file.Close()

			ctx := context.Background()
			doc, err := sbom.NewSBOMDocument(ctx, file, sbom.Signature{})
			require.NoError(t, err)
			require.NotNil(t, doc)

			// Load and apply policy
			policies, err := policy.LoadPoliciesFromFile(tc.PolicyFile)
			require.NoError(t, err)
			require.NotEmpty(t, policies)

			// Initialize extractor
			extractor := policy.NewExtractor(doc)
			extractor.MapFieldWithFunction(ctx)

			// Evaluate all policies
			var results []policy.PolicyResult
			for _, p := range policies {
				result, err := policy.EvaluatePolicyAgainstSBOMs(ctx, p, doc, extractor)
				require.NoError(t, err)
				results = append(results, result)
			}

			// Check overall result
			allPassed := true
			totalViolations := 0
			for _, result := range results {
				if result.OverallResult == "fail" {
					allPassed = false
				}
				totalViolations += result.ViolationCnt
			}

			// Verify pass/fail
			if tc.ExpectedPass {
				assert.True(t, allPassed, "Expected policy to pass but it failed")
			} else {
				assert.False(t, allPassed, "Expected policy to fail but it passed")
			}

			// Verify violation count if specified
			if tc.ExpectedViolations > 0 {
				assert.Equal(t, tc.ExpectedViolations, totalViolations,
					"Expected %d violations but got %d", tc.ExpectedViolations, totalViolations)
			}

			// Verify specific field was checked
			if tc.CheckField != "" {
				fieldChecked := false
				for _, result := range results {
					for _, check := range result.RuleResults {
						if check.DeclaredField == tc.CheckField {
							fieldChecked = true
							break
						}
					}
				}
				assert.True(t, fieldChecked, "Field %s was not checked", tc.CheckField)
			}

			t.Logf("File: %s | Policy: %s | Result: %v | Violations: %d",
				filepath.Base(tc.SBOMFile),
				filepath.Base(tc.PolicyFile),
				allPassed,
				totalViolations)
		})
	}
}

// TestPolicyFieldExtraction validates that fields are correctly extracted from SPDX 3.0
func TestPolicyFieldExtractionSPDX3(t *testing.T) {
	base := filepath.Join("..", "..", "testdata", "fixtures")

	testCases := []struct {
		name            string
		sbomFile        string
		field           string
		level           string // "doc" or "comp"
		expectedPresent bool
	}{
		{
			name:            "SPDX3 perfect score has document authors",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "sbom_authors",
			level:           "doc",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 no-authors missing document authors",
			sbomFile:        filepath.Join(base, "spdx3-no-authors.json"),
			field:           "sbom_authors",
			level:           "doc",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 perfect score has component supplier",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "supplier",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 no-supplier missing component supplier",
			sbomFile:        filepath.Join(base, "spdx3-no-supplier.json"),
			field:           "supplier",
			level:           "comp",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 perfect score has component PURL",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "purl",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 no-unique-id missing component PURL",
			sbomFile:        filepath.Join(base, "spdx3-no-unique-id.json"),
			field:           "purl",
			level:           "comp",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 perfect score has component CPE",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "cpe",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 perfect score has component copyright",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "copyright",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 perfect score has component download location",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "downloadlocation",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 perfect score has component type",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "type",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 perfect score has component checksum",
			sbomFile:        filepath.Join(base, "spdx3-perfect-score.json"),
			field:           "checksum",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 no-checksum missing component checksum",
			sbomFile:        filepath.Join(base, "spdx3-no-checksum.json"),
			field:           "checksum",
			level:           "comp",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 no-cpe missing component CPE",
			sbomFile:        filepath.Join(base, "spdx3-no-cpe.json"),
			field:           "cpe",
			level:           "comp",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 no-copyright missing component copyright",
			sbomFile:        filepath.Join(base, "spdx3-no-copyright.json"),
			field:           "copyright",
			level:           "comp",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 no-downloadlocation missing component download location",
			sbomFile:        filepath.Join(base, "spdx3-no-downloadlocation.json"),
			field:           "downloadlocation",
			level:           "comp",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 no-type missing component type",
			sbomFile:        filepath.Join(base, "spdx3-no-type.json"),
			field:           "type",
			level:           "comp",
			expectedPresent: false,
		},
		{
			name:            "SPDX3 with declared licenses has component declared license",
			sbomFile:        filepath.Join(base, "spdx3-with-declared-concluded-licenses.json"),
			field:           "declared_license",
			level:           "comp",
			expectedPresent: true,
		},
		{
			name:            "SPDX3 with concluded licenses has component concluded license",
			sbomFile:        filepath.Join(base, "spdx3-with-declared-concluded-licenses.json"),
			field:           "concluded_license",
			level:           "comp",
			expectedPresent: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.Open(tc.sbomFile)
			require.NoError(t, err)
			defer file.Close()

			ctx := context.Background()
			doc, err := sbom.NewSBOMDocument(ctx, file, sbom.Signature{})
			require.NoError(t, err)

			extractor := policy.NewExtractor(doc)
			extractor.MapFieldWithFunction(ctx)

			var present bool
			if tc.level == "doc" {
				// Document-level field
				values := extractor.RetrieveValues(nil, tc.field)
				present = len(values) > 0
			} else {
				// Component-level field - check all components
				for _, comp := range doc.Components() {
					values := extractor.RetrieveValues(comp, tc.field)
					if len(values) > 0 {
						present = true
						break
					}
				}
			}

			assert.Equal(t, tc.expectedPresent, present,
				"Field %s present=%v, expected=%v", tc.field, present, tc.expectedPresent)
		})
	}
}
