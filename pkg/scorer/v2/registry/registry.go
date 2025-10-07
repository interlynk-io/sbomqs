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

package registry

import (
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
)

var SupportedFeatures = map[string]bool{
	"comp_with_name":             true,
	"comp_with_version":          true,
	"comp_with_identifiers":      true,
	"sbom_creation_timestamp":    true,
	"sbom_authors":               true,
	"sbom_tool_version":          true,
	"sbom_supplier":              true,
	"sbom_namespace":             true,
	"sbom_lifecycle":             true,
	"comp_with_checksums":        true,
	"comp_with_sha256":           true,
	"sbom_signature":             true,
	"comp_with_dependencies":     true,
	"sbom_completeness_declared": true,
	"primary_component":          true,
	"comp_with_source_code":      true,
	"comp_with_supplier":         true,
	"comp_with_purpose":          true,
	"comp_with_licenses":         true,

	"comp_with_valid_licenses":     true,
	"comp_with_declared_licenses":  true,
	"sbom_data_license":            true,
	"comp_no_deprecated_licenses":  true,
	"comp_no_restrictive_licenses": true,
	"comp_with_purl":               true,
	"comp_with_cpe":                true,
	"sbom_spec_declared":           true,
	"sbom_spec_version":            true,
	"sbom_file_format":             true,
	"sbom_schema_valid":            true,
}

var CategoryAliases = map[string]string{
	"identification": "Identification",
	"provenance":     "Provenance",
	"integrity":      "Integrity",
	"completeness":   "Completeness",
	"licensing":      "LicensingAndCompliance",
	"vulnerability":  "VulnerabilityAndTraceability",
	"structural":     "Structural",
}

var SupportedCategories = map[string]bool{
	"Identification":               true,
	"Provenance":                   true,
	"Integrity":                    true,
	"Completeness":                 true,
	"LicensingAndCompliance":       true,
	"VulnerabilityAndTraceability": true,
	"Structural":                   true,
}

func BaseCategories() []config.CategorySpec {
	return []config.CategorySpec{
		Identification,
		Provenance,
		Integrity,
		Completeness,
		LicensingAndCompliance,
		VulnerabilityAndTraceability,
		Structural,
		ComponentAndQualityInfo,
	}
}

var Identification = config.CategorySpec{
	Name:   "Identification",
	Weight: 10,
	Features: []config.FeatureSpec{
		{Key: "comp_with_name", Weight: 0.40, Evaluate: nil},
		{Key: "comp_with_version", Weight: 0.35, Evaluate: nil},
		{Key: "comp_with_ids", Weight: 0.25, Evaluate: nil},
	},
}

var Provenance = config.CategorySpec{
	Name:   "Provenance",
	Weight: 12,
	Features: []config.FeatureSpec{
		{Key: "sbom_creation_timestamp", Weight: 0.20, Evaluate: nil},
		{Key: "sbom_authors", Weight: 0.20, Evaluate: nil},
		{Key: "sbom_tool_version", Weight: 0.20, Evaluate: nil},
		{Key: "sbom_supplier", Weight: 0.15, Evaluate: nil},
		{Key: "sbom_namespace", Weight: 0.15, Evaluate: nil},
		{Key: "sbom_lifecycle", Weight: 0.10, Evaluate: nil},
	},
}

var Integrity = config.CategorySpec{
	Name:     "Integrity",
	Weight:   15,
	Features: []config.FeatureSpec{
		// {Key: "sbom_signature", Weight: 0.10, Evaluate: SBOMDDocSignature},
		// {Key: "component_hash", Weight: 0.10, Evaluate: CompWithChecksum},
	},
}

var Completeness = config.CategorySpec{
	Name:     "Completeness",
	Weight:   12,
	Features: nil,
}

var LicensingAndCompliance = config.CategorySpec{
	Name:     "Licensing & Compliance",
	Weight:   15,
	Features: nil,
}

var VulnerabilityAndTraceability = config.CategorySpec{
	Name:     "Vulnerability & Traceability",
	Weight:   10,
	Features: nil,
}

var Structural = config.CategorySpec{
	Name:     "Structural",
	Weight:   8,
	Features: nil,
}

var ComponentAndQualityInfo = config.CategorySpec{
	Name:     "Component Quality (Info)",
	Weight:   0,
	Features: nil,
}
