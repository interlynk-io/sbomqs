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

package v2

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

func baseCategories() []CategorySpec {
	return []CategorySpec{
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

var Identification = CategorySpec{
	Name:   "Identification",
	Weight: 10,
	Features: []FeatureSpec{
		{Key: "comp_with_name", Weight: 0.40, Evaluate: CompWithName},
		{Key: "comp_with_version", Weight: 0.35, Evaluate: CompWithVersion},
		{Key: "comp_with_ids", Weight: 0.25, Evaluate: CompWithUniqIDs},
	},
}

var Provenance = CategorySpec{
	Name:   "Provenance",
	Weight: 12,
	Features: []FeatureSpec{
		{Key: "sbom_creation_timestamp", Weight: 0.20, Evaluate: SBOMCreationTime},
		{Key: "sbom_authors", Weight: 0.20, Evaluate: SBOMAuthors},
		{Key: "sbom_tool_version", Weight: 0.20, Evaluate: SBOMToolVersion},
		{Key: "sbom_supplier", Weight: 0.15, Evaluate: SBOMSupplier},
		{Key: "sbom_namespace", Weight: 0.15, Evaluate: SBOMNamespace},
		{Key: "sbom_lifecycle", Weight: 0.10, Evaluate: SBOMLifecycle},
	},
}

var Integrity = CategorySpec{
	Name:     "Integrity",
	Weight:   15,
	Features: []FeatureSpec{
		// {Key: "sbom_signature", Weight: 0.10, Evaluate: SBOMDDocSignature},
		// {Key: "component_hash", Weight: 0.10, Evaluate: CompWithChecksum},
	},
}

var Completeness = CategorySpec{
	Name:     "Completeness",
	Weight:   12,
	Features: nil,
}

var LicensingAndCompliance = CategorySpec{
	Name:     "Licensing & Compliance",
	Weight:   15,
	Features: nil,
}

var VulnerabilityAndTraceability = CategorySpec{
	Name:     "Vulnerability & Traceability",
	Weight:   10,
	Features: nil,
}

var Structural = CategorySpec{
	Name:     "Structural",
	Weight:   8,
	Features: nil,
}

var ComponentAndQualityInfo = CategorySpec{
	Name:     "Component Quality (Info)",
	Weight:   0,
	Features: nil,
}
