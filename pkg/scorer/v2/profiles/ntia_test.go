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

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

func TestCompWithSupplier(t *testing.T) {
	testCases := []struct {
		name          string
		doc           sbom.Document
		expectedScore float64
		expectedDesc  string
	}{
		{
			name:          "All components have suppliers",
			doc:           createDocWithAllSuppliers(),
			expectedScore: 10.0,
			expectedDesc:  "complete",
		},
		{
			name:          "Half components have suppliers",
			doc:           createDocWithHalfSuppliers(),
			expectedScore: 5.0,
			expectedDesc:  "add to 1 component",
		},
		{
			name:          "No components have suppliers",
			doc:           createDocWithNoSuppliers(),
			expectedScore: 0.0,
			expectedDesc:  "add to 2 components",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := CompWithSupplier(tc.doc)
			if result.Score != tc.expectedScore {
				t.Errorf("Expected score %f, got %f", tc.expectedScore, result.Score)
			}
			if result.Desc != tc.expectedDesc {
				t.Errorf("Expected desc '%s', got '%s'", tc.expectedDesc, result.Desc)
			}
		})
	}
}

func TestNTIAOptionalFields(t *testing.T) {
	doc := createDocWithOptionalFields()

	t.Run("Component Hash (optional)", func(t *testing.T) {
		result := NTIACompHash(doc)
		// Optional fields now return scores for display but shouldn't impact overall score
		if result.Score < 0.0 || result.Score > 10.0 {
			t.Errorf("Optional field score should be between 0-10, got %f", result.Score)
		}
		// Check that description is appropriate
		if result.Desc == "" {
			t.Errorf("Optional field desc should not be empty")
		}
	})

	t.Run("SBOM Lifecycle (optional)", func(t *testing.T) {
		result := NTIASBOMLifecycle(doc)
		if result.Score < 0.0 || result.Score > 10.0 {
			t.Errorf("Optional field score should be between 0-10, got %f", result.Score)
		}
		if result.Desc == "" {
			t.Errorf("Optional field desc should not be empty")
		}
	})

	t.Run("Component Relationships (optional)", func(t *testing.T) {
		result := NTIACompRelationships(doc)
		if result.Score < 0.0 || result.Score > 10.0 {
			t.Errorf("Optional field score should be between 0-10, got %f", result.Score)
		}
		if result.Desc == "" {
			t.Errorf("Optional field desc should not be empty")
		}
	})

	t.Run("Component License (optional)", func(t *testing.T) {
		result := NTIACompLicense(doc)
		if result.Score < 0.0 || result.Score > 10.0 {
			t.Errorf("Optional field score should be between 0-10, got %f", result.Score)
		}
		if result.Desc == "" {
			t.Errorf("Optional field desc should not be empty")
		}
	})
}

// Helper functions to create test documents
func createDocWithAllSuppliers() sbom.Document {
	comp1 := sbom.Component{
		Name:    "comp1",
		Version: "1.0",
		Supplier: sbom.Supplier{
			Name: "Supplier1",
		},
	}
	comp2 := sbom.Component{
		Name:    "comp2", 
		Version: "2.0",
		Supplier: sbom.Supplier{
			Email: "supplier2@example.com",
		},
	}
	
	return sbom.SpdxDoc{
		Comps: []sbom.GetComponent{comp1, comp2},
	}
}

func createDocWithHalfSuppliers() sbom.Document {
	comp1 := sbom.Component{
		Name:    "comp1",
		Version: "1.0",
		Supplier: sbom.Supplier{
			Name: "Supplier1",
		},
	}
	comp2 := sbom.Component{
		Name:    "comp2",
		Version: "2.0",
		// No supplier
	}
	
	return sbom.SpdxDoc{
		Comps: []sbom.GetComponent{comp1, comp2},
	}
}

func createDocWithNoSuppliers() sbom.Document {
	comp1 := sbom.Component{
		Name:    "comp1",
		Version: "1.0",
	}
	comp2 := sbom.Component{
		Name:    "comp2",
		Version: "2.0",
	}
	
	return sbom.SpdxDoc{
		Comps: []sbom.GetComponent{comp1, comp2},
	}
}

func createDocWithOptionalFields() sbom.Document {
	chk1 := sbom.Checksum{
		Alg:     "SHA-256",
		Content: "abc123",
	}
	
	comp1 := sbom.Component{
		Name:             "comp1",
		Version:          "1.0",
		Checksums:        []sbom.GetChecksum{chk1},
		HasRelationships: true, // Has relationships
	}
	
	return sbom.SpdxDoc{
		Comps:     []sbom.GetComponent{comp1},
		Lifecycle: "build", // Has lifecycle
	}
}