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

package score

import (
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/extractors"
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
		{Key: "comp_with_name", Weight: 0.40, Evaluate: extractors.CompWithName},
		{Key: "comp_with_version", Weight: 0.35, Evaluate: extractors.CompWithCompleteness},
		{Key: "comp_with_ids", Weight: 0.25, Evaluate: extractors.CompWithUniqLocalIDs},
	},
}

var Provenance = config.CategorySpec{
	Name:   "Provenance",
	Weight: 12,
	Features: []config.FeatureSpec{
		{Key: "sbom_creation_timestamp", Weight: 0.20, Evaluate: extractors.SBOMCreationTimestamp},
		{Key: "sbom_authors", Weight: 0.20, Evaluate: extractors.SBOMAuthors},
		{Key: "sbom_tool_version", Weight: 0.20, Evaluate: extractors.SBOMCreationTool},
		{Key: "sbom_supplier", Weight: 0.15, Evaluate: extractors.SBOMSupplier},
		{Key: "sbom_namespace", Weight: 0.15, Evaluate: extractors.SBOMNamespace},
		{Key: "sbom_lifecycle", Weight: 0.10, Evaluate: extractors.SBOMLifeCycle},
	},
}

var Integrity = config.CategorySpec{
	Name:   "Integrity",
	Weight: 15,
	Features: []config.FeatureSpec{
		{Key: "sbom_signature", Weight: 0.10, Evaluate: extractors.SBOMSignature},
		{Key: "comp_with_checksums", Weight: 0.60, Evaluate: extractors.CompWithSHA1Plus},
		{Key: "comp_with_sha256", Weight: 0.30, Evaluate: extractors.CompWithSHA256Plus},
	},
}

var Completeness = config.CategorySpec{
	Name:   "Completeness",
	Weight: 12,
	Features: []config.FeatureSpec{
		{Key: "comp_with_dependencies", Weight: 0.25, Evaluate: extractors.CompWithDependencies},
		{Key: "sbom_completeness_declared", Weight: 0.15, Evaluate: extractors.CompWithCompleteness},
		{Key: "primary_component", Weight: 0.20, Evaluate: extractors.SBOMWithPrimaryComponent},
		{Key: "comp_with_source_code", Weight: 0.15, Evaluate: extractors.CompWithSourceCode},
		{Key: "comp_with_supplier", Weight: 0.15, Evaluate: extractors.CompWithSupplier},
		{Key: "comp_with_purpose", Weight: 0.10, Evaluate: extractors.CompWithPackagePurpose},
	},
}

var LicensingAndCompliance = config.CategorySpec{
	Name:   "Licensing & Compliance",
	Weight: 15,
	Features: []config.FeatureSpec{
		{Key: "comp_with_licenses", Weight: 0.20, Evaluate: extractors.CompWithLicenses},
		{Key: "comp_with_valid_licenses", Weight: 0.20, Evaluate: extractors.CompWithValidLicenses},
		{Key: "comp_with_declared_licenses", Weight: 0.15, Evaluate: extractors.CompWithDeclaredLicenses},
		{Key: "sbom_data_license", Weight: 0.10, Evaluate: extractors.SBOMDataLicense},
		{Key: "comp_no_deprecated_licenses", Weight: 0.15, Evaluate: extractors.CompWithDeprecatedLicenses},
		{Key: "comp_no_restrictive_licenses", Weight: 0.20, Evaluate: extractors.CompWithRestrictiveLicenses},
	},
}

var VulnerabilityAndTraceability = config.CategorySpec{
	Name:   "Vulnerability & Traceability",
	Weight: 10,
	Features: []config.FeatureSpec{
		{Key: "CompWithPURL", Weight: 0.50, Evaluate: extractors.CompWithPURL},
		{Key: "CompWithCPE", Weight: 0.50, Evaluate: extractors.CompWithCPE},
	},
}

var Structural = config.CategorySpec{
	Name:   "Structural",
	Weight: 8,
	Features: []config.FeatureSpec{
		{Key: "SBOMWithSpec", Weight: 0.30, Evaluate: extractors.SBOMWithSpec},
		{Key: "SBOMSpecVersion", Weight: 0.30, Evaluate: extractors.SBOMSpecVersion},
		{Key: "SBOMFileFormat", Weight: 0.20, Evaluate: extractors.SBOMFileFormat},
		{Key: "SBOMSchemaValid", Weight: 0.20, Evaluate: extractors.SBOMSchemaValid},
	},
}

var ComponentAndQualityInfo = config.CategorySpec{
	Name:     "Component Quality (Info)",
	Weight:   0,
	Features: nil,
}
