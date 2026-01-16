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
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// Automation Support
func SBOMWithAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAutomationSpec(doc)
}

// Dependency Relationships
func SbomWithDepedencies(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMDepedencies(doc)
}

// SBOM Author
func SbomWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

// SBOM Timestamp
func SbomWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

// Component Name
func CompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// Component Version
func CompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// Component Supplier
func CompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {
	return CompSupplier(doc)
}

// Component Other Identifiers
func CompWithUniqID(doc sbom.Document) catalog.ProfFeatScore {
	return CompUniqID(doc)
}

// NTIA Optional Fields - These don't impact overall scoring but show field coverage

// Component Hash (SHOULD)
func NTIACompHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompHash(doc)
}

// SBOM Lifecycle (SHOULD)
func NTIASBOMLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	lifecycles := doc.Lifecycles()
	if len(lifecycles) > 0 {
		return catalog.ProfFeatScore{
			Score: 10.0,
			Desc:  "complete",
		}
	}
	return catalog.ProfFeatScore{
		Score: 0.0,
		Desc:  "add lifecycle phase",
	}
}

// NTIA intent:
// - Relationships declared for the Primary Component
// - Relationships declared for its direct Dependencies
// - Leaf dependencies valid and transitive components mdeps doesn't matter
func NTIACompRelationships(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return formulae.ScoreProfileCustomNA(false, "define primary component")

	}

	// 1. Get direct dependencies of the primary component
	primaryDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
	if len(primaryDeps) == 0 {
		return formulae.ScoreProfNA(false)
	}

	// 2. Count how many of those dependencies declare relationships themselves
	have := lo.CountBy(primaryDeps, func(c sbom.GetComponent) bool {
		return len(doc.GetDirectDependencies(c.GetID(), "DEPENDS_ON")) > 0
	})

	return formulae.ScoreProfFull(have, len(primaryDeps), false)
}

// // Component Relationships (SHOULD)
// func NTIACompRelationships(doc sbom.Document) catalog.ProfFeatScore {
// 	comps := doc.Components()
// 	if len(comps) == 0 {
// 		return catalog.ProfFeatScore{
// 			Score: 0.0,
// 			Desc:  formulae.NoComponentsNA(),
// 		}
// 	}

// 	have := 0
// 	for _, comp := range comps {
// 		// Check for pedigree info in CycloneDX or additional relationships in SPDX
// 		if comp.HasRelationShips() {
// 			have++
// 		}
// 	}

// 	total := len(comps)
// 	score := (float64(have) / float64(total)) * 10.0

// 	return catalog.ProfFeatScore{
// 		Score: score,
// 		Desc:  formulae.CompDescription(have, total),
// 	}
// }

// Component License (SHOULD)
func NTIACompLicense(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  formulae.NoComponentsNA(),
		}
	}

	have := 0
	for _, c := range comps {
		licenses := c.GetLicenses()
		if len(licenses) > 0 {
			have++
		}
	}

	total := len(comps)
	score := (float64(have) / float64(total)) * 10.0

	return catalog.ProfFeatScore{
		Score: score,
		Desc:  formulae.CompDescription(have, total),
	}
}
