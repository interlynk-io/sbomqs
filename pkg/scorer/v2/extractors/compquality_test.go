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
	"testing"

	"github.com/interlynk-io/sbomqs/v2/pkg/interlynkapi"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a pointer to int
func ptrInt(i int) *int {
	return &i
}

// buildCompQuality creates a ComponentQualityResult simulating API findings for components.
// findingsMap: component index -> list of findings for that component
func buildCompQuality(totalComponents int, findingsMap map[int][]interlynkapi.Finding) *interlynkapi.ComponentQualityResult {
	return &interlynkapi.ComponentQualityResult{
		FindingsByCompIndex: findingsMap,
		TotalComponents:     totalComponents,
		Tier:                "unauthenticated",
	}
}

// Test with no ComponentQuality (API not called)
func TestCompWithPurlValid_NoAPIResult(t *testing.T) {
	ctx := context.Background()

	// SBOM with components that have PURLs
	cdxWithPurls := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "pkg-a", "version": "1.0.0", "purl": "pkg:npm/pkg-a@1.0.0"},
			{"type": "library", "name": "pkg-b", "version": "2.0.0", "purl": "pkg:npm/pkg-b@2.0.0"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPurls, sbom.Signature{})
	require.NoError(t, err)

	// No ComponentQuality - simulates --url not provided or API call skipped
	input := catalog.EvalInput{Doc: doc}
	got := CompWithPurlValid(ctx, input)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "N/A", got.Desc)
	assert.True(t, got.Ignore)
}

// Test with ComponentQuality but no findings (API verified all components passed)
func TestCompWithPurlValid_AllValid(t *testing.T) {
	ctx := context.Background()

	cdxWithPurls := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "pkg-a", "version": "1.0.0", "purl": "pkg:npm/pkg-a@1.0.0"},
			{"type": "library", "name": "pkg-b", "version": "2.0.0", "purl": "pkg:npm/pkg-b@2.0.0"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPurls, sbom.Signature{})
	require.NoError(t, err)

	// API returned findings for both components, but no PURL-related findings
	// (e.g., only CPE findings or other checks)
	cq := buildCompQuality(2, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-CPE-001", Severity: "medium"}}, // not a PURL finding
		1: {{Index: ptrInt(1), CheckCode: "IDT-CPE-002", Severity: "low"}},    // not a PURL finding
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	assert.InDelta(t, 10.0, got.Score, 1e-9)
	assert.Equal(t, "complete", got.Desc)
	assert.False(t, got.Ignore)
}

// Test with one valid PURL and one invalid
func TestCompWithPurlValid_OneValidOneInvalid(t *testing.T) {
	ctx := context.Background()

	cdxWithPurls := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "valid-pkg", "version": "1.0.0", "purl": "pkg:npm/valid-pkg@1.0.0"},
			{"type": "library", "name": "invalid-pkg", "version": "2.0.0", "purl": "not-a-valid-purl@2.0.0"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPurls, sbom.Signature{})
	require.NoError(t, err)

	// API found that component 1 has an invalid PURL
	cq := buildCompQuality(2, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-CPE-001", Severity: "medium"}}, // passes PURL check
		1: {{Index: ptrInt(1), CheckCode: "IDT-PURL-001", Severity: "high"}},  // fails PURL check
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
	assert.False(t, got.Ignore)
}

// Test with all PURLs invalid
func TestCompWithPurlValid_AllInvalid(t *testing.T) {
	ctx := context.Background()

	cdxWithPurls := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "pkg-a", "version": "1.0.0", "purl": "invalid1"},
			{"type": "library", "name": "pkg-b", "version": "2.0.0", "purl": "invalid2"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPurls, sbom.Signature{})
	require.NoError(t, err)

	// Both components have PURL findings
	cq := buildCompQuality(2, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-PURL-001", Severity: "high"}},
		1: {{Index: ptrInt(1), CheckCode: "IDT-PURL-002", Severity: "critical"}},
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "add to 2 components", got.Desc)
	assert.False(t, got.Ignore)
}

// Test SPDX format
func TestCompWithPurlValid_SPDXFormat(t *testing.T) {
	ctx := context.Background()

	spdxWithPurls := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-sbom",
		"creationInfo": {
			"created": "2025-01-01T00:00:00Z",
			"creators": ["Tool: test"]
		},
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-1",
				"name": "pkg-a",
				"versionInfo": "1.0.0",
				"externalRefs": [
					{
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/pkg-a@1.0.0",
						"referenceCategory": "PACKAGE-MANAGER"
					}
				]
			}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, spdxWithPurls, sbom.Signature{})
	require.NoError(t, err)

	// Component has no PURL findings (valid PURL)
	cq := buildCompQuality(1, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-CPE-001", Severity: "medium"}},
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	assert.InDelta(t, 10.0, got.Score, 1e-9)
	assert.Equal(t, "complete", got.Desc)
	assert.False(t, got.Ignore)
}

// Test empty SBOM (no components)
func TestCompWithPurlValid_EmptySBOM(t *testing.T) {
	ctx := context.Background()

	emptyCdx := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": []
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, emptyCdx, sbom.Signature{})
	require.NoError(t, err)

	cq := buildCompQuality(0, map[int][]interlynkapi.Finding{})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "N/A (no components)", got.Desc)
	assert.True(t, got.Ignore)
}

// Test SBOM where some components have no findings (unverified)
func TestCompWithPurlValid_PartialVerification(t *testing.T) {
	ctx := context.Background()

	cdxWithPurls := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "pkg-a", "version": "1.0.0", "purl": "pkg:npm/pkg-a@1.0.0"},
			{"type": "library", "name": "pkg-b", "version": "2.0.0", "purl": "pkg:npm/pkg-b@2.0.0"},
			{"type": "library", "name": "pkg-c", "version": "3.0.0", "purl": "pkg:npm/pkg-c@3.0.0"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPurls, sbom.Signature{})
	require.NoError(t, err)

	// Only component 0 was verified by API and has a PURL finding
	// Components 1 and 2 have no findings - they're unverified and not counted
	cq := buildCompQuality(3, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-PURL-001", Severity: "high"}},
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	// Only 1 component verified, and it failed
	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
	assert.False(t, got.Ignore)
}

// Test multiple findings for same component (should only count once)
func TestCompWithPurlValid_MultipleFindingsSameComponent(t *testing.T) {
	ctx := context.Background()

	cdxWithPurls := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "pkg-a", "version": "1.0.0", "purl": "pkg:npm/pkg-a@1.0.0"},
			{"type": "library", "name": "pkg-b", "version": "2.0.0", "purl": "pkg:npm/pkg-b@2.0.0"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithPurls, sbom.Signature{})
	require.NoError(t, err)

	// Component 0 has multiple PURL findings - should only count as one failure
	cq := buildCompQuality(2, map[int][]interlynkapi.Finding{
		0: {
			{Index: ptrInt(0), CheckCode: "IDT-PURL-001", Severity: "high"},
			{Index: ptrInt(0), CheckCode: "IDT-PURL-002", Severity: "medium"},
		},
		1: {{Index: ptrInt(1), CheckCode: "IDT-CPE-001", Severity: "low"}}, // passes PURL
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	// 1 passing (component 1), 1 failing (component 0)
	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
	assert.False(t, got.Ignore)
}

// CPE Tests - similar patterns
func TestCompWithCpeValid_NoAPIResult(t *testing.T) {
	ctx := context.Background()

	cdxWithCpes := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "pkg-a", "version": "1.0.0", "cpe": "cpe:2.3:a:vendor:pkg-a:1.0.0:*:*:*:*:*:*:*"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithCpes, sbom.Signature{})
	require.NoError(t, err)

	input := catalog.EvalInput{Doc: doc}
	got := CompWithCpeValid(ctx, input)

	assert.InDelta(t, 0.0, got.Score, 1e-9)
	assert.Equal(t, "N/A", got.Desc)
	assert.True(t, got.Ignore)
}

func TestCompWithCpeValid_AllValid(t *testing.T) {
	ctx := context.Background()

	cdxWithCpes := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "pkg-a", "version": "1.0.0", "cpe": "cpe:2.3:a:vendor:pkg-a:1.0.0:*:*:*:*:*:*:*"},
			{"type": "library", "name": "pkg-b", "version": "2.0.0", "cpe": "cpe:2.3:a:vendor:pkg-b:2.0.0:*:*:*:*:*:*:*"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithCpes, sbom.Signature{})
	require.NoError(t, err)

	// No CPE findings - all valid
	cq := buildCompQuality(2, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-PURL-001", Severity: "medium"}},
		1: {{Index: ptrInt(1), CheckCode: "IDT-PURL-002", Severity: "low"}},
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithCpeValid(ctx, input)

	assert.InDelta(t, 10.0, got.Score, 1e-9)
	assert.Equal(t, "complete", got.Desc)
	assert.False(t, got.Ignore)
}

func TestCompWithCpeValid_MixedResults(t *testing.T) {
	ctx := context.Background()

	cdxWithCpes := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "valid-cpe", "version": "1.0.0", "cpe": "cpe:2.3:a:vendor:valid:1.0.0:*:*:*:*:*:*:*"},
			{"type": "library", "name": "invalid-cpe", "version": "2.0.0", "cpe": "cpe:2.3:a:vendor:invalid:2.0.0:*:*:*:*:*:*:*"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdxWithCpes, sbom.Signature{})
	require.NoError(t, err)

	cq := buildCompQuality(2, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-PURL-001", Severity: "medium"}}, // passes CPE
		1: {{Index: ptrInt(1), CheckCode: "IDT-CPE-001", Severity: "high"}},    // fails CPE
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithCpeValid(ctx, input)

	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
	assert.False(t, got.Ignore)
}

// Test showing how API result maps to actual SBOM components
func TestCompWithPurlValid_RealisticFlow(t *testing.T) {
	ctx := context.Background()

	// Real SBOM with 3 components
	cdx := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"serialNumber": "urn:uuid:test",
		"version": 1,
		"components": [
			{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
			{"type": "library", "name": "react", "version": "18.0.0", "purl": "pkg:npm/react@18.0.0"},
			{"type": "library", "name": "axios", "version": "0.27.0", "purl": "pkg:npm/axios@0.27.0"}
		]
	}`)

	doc, err := sbom.NewSBOMDocumentFromBytes(ctx, cdx, sbom.Signature{})
	require.NoError(t, err)

	// Simulate API response: first 2 components checked, 1 had PURL issue
	// Component 2 (axios) wasn't checked by API (no entry in map)
	cq := buildCompQuality(3, map[int][]interlynkapi.Finding{
		0: {{Index: ptrInt(0), CheckCode: "IDT-PURL-001", Message: "PURL not resolvable"}}, // lodash fails
		1: {{Index: ptrInt(1), CheckCode: "IDT-CPE-001", Severity: "low"}},                 // react passes PURL
		// axios (index 2) not verified - no entry
	})

	input := catalog.EvalInput{Doc: doc, ComponentQuality: cq}
	got := CompWithPurlValid(ctx, input)

	// Only 2 components verified, 1 passed
	assert.InDelta(t, 5.0, got.Score, 1e-9)
	assert.Equal(t, "add to 1 component", got.Desc)
	assert.False(t, got.Ignore)
}

// Test constant values
func TestCheckCodeConstants(t *testing.T) {
	assert.Equal(t, "IDT-PURL-", PURLCode)
	assert.Equal(t, "IDT-CPE-", CPECode)
}
