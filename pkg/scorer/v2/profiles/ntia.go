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
	"slices"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// // Automation Support
// func SBOMWithAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMAutomationSpec(doc)
// }

// Component Supplier
func CompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {

	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		supplier := c.Suppliers()
		if supplier != nil {
			hasName := strings.TrimSpace(supplier.GetName()) != ""
			hasURL := strings.TrimSpace(supplier.GetURL()) != ""
			hasEmail := strings.TrimSpace(supplier.GetEmail()) != ""

			if hasName || hasURL || hasEmail {
				return true
			}
		}

		manufacturer := c.Manufacturer()
		if manufacturer != nil {
			hasName := strings.TrimSpace(manufacturer.GetName()) != ""
			hasURL := strings.TrimSpace(manufacturer.GetURL()) != ""
			hasEmail := strings.TrimSpace(manufacturer.GetEmail()) != ""

			if hasName || hasURL || hasEmail {
				return true
			}
		}

		return false
	})

	return formulae.ScoreProfFull(have, len(comps), false)
}

// CompWithName check for component with name
func CompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// CompWithVersion check for Component with Version
func CompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// CompWithUniqID checks Component Other Identifiers such as PURL/CPE
func CompWithUniqID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return checkUniqueIDs(c)
	})

	return formulae.ScoreProfFull(have, len(comps), false)
}

// NTIASBOMRelationships evaluates SBOM-level dependency requirements
// as defined by NTIA Minimum Elements
//
// NTIA requires:
//   - Identification of upstream (DEPENDS_ON) relationships
//     for the primary component
//
// NTIA does NOT require:
//   - Complete transitive dependency graphs
//   - Dependency declarations for every component
func NTIASBOMRelationships(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return formulae.ScoreProfileCustomNA(false, "define primary component")
	}

	// 1. Get direct dependencies of the primary component
	// if the primary component declares at least one direct dependency,
	// NTIA dependency requirement is satisfied
	directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
	if len(directDeps) > 0 {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "primary component has direct relationships",
			Ignore: false,
		}
	}

	// 2. no direct dependencies --> check declared completeness
	for _, c := range doc.Composition() {

		if c.Scope() != sbom.ScopeDependencies {
			continue
		}

		// Composition applies to primary component
		if !slices.Contains(c.Dependencies(), primary.GetID()) {
			continue
		}

		switch c.Aggregate() {
		case sbom.AggregateComplete:
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "primary comp declares relationships completeness complete",
				Ignore: false,
			}

		case sbom.AggregateUnknown:
			return catalog.ProfFeatScore{
				Score:  5.0,
				Desc:   "primary comp declares relationships completeness unknown",
				Ignore: false,
			}

		case sbom.AggregateIncomplete:
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "primary comp declares relationships completeness incomplete",
				Ignore: false,
			}
		}
	}

	// 3. No dependencies and no completeness declaration
	// Default interpretation per NTIA: incomplete
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "primary component has no direct relationships and does not declare completeness",
		Ignore: false,
	}
}

// SBOM Author
func SbomWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	authors := doc.Authors()

	if len(authors) > 0 {
		for _, author := range authors {
			name := strings.TrimSpace(author.GetName())
			email := strings.TrimSpace(author.GetEmail())

			if name != "" || email != "" {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "SBOM author present",
					Ignore: false,
				}
			}
		}
	}

	tools := doc.Tools()
	if len(tools) > 0 {
		for _, tool := range tools {
			name := strings.TrimSpace(tool.GetName())
			version := strings.TrimSpace(tool.GetVersion())

			if name != "" && version != "" {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "SBOM tool present",
					Ignore: false,
				}
			} else if name != "" {
				return catalog.ProfFeatScore{
					Score:  5.0,
					Desc:   "SBOM tool name present only",
					Ignore: false,
				}
			} else if version != "" {
				return catalog.ProfFeatScore{
					Score:  0.0,
					Desc:   "SBOM tool version present only",
					Ignore: false,
				}
			}
		}
	}

	supplier := doc.Supplier()
	if supplier != nil {
		name := strings.TrimSpace(supplier.GetName())
		email := strings.TrimSpace(supplier.GetEmail())
		url := strings.TrimSpace(supplier.GetURL())

		if name != "" || email != "" || url != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "supplier used as SBOM author fallback",
				Ignore: false,
			}
		}
	}

	manufacturer := doc.Manufacturer()
	if manufacturer != nil {
		name := strings.TrimSpace(manufacturer.GetName())
		email := strings.TrimSpace(manufacturer.GetEmail())
		url := strings.TrimSpace(manufacturer.GetURL())

		if name != "" || email != "" || url != "" {
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "manufacturer used as SBOM author fallback",
				Ignore: false,
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "add author information",
		Ignore: false,
	}
}

// SBOM Timestamp
func SbomWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

// // NTIA Optional Fields - These don't impact overall scoring but show field coverage

// // Component Hash (SHOULD)
// func NTIACompHash(doc sbom.Document) catalog.ProfFeatScore {
// 	return CompHash(doc)
// }

// // SBOM Lifecycle (SHOULD)
// func NTIASBOMLifecycle(doc sbom.Document) catalog.ProfFeatScore {
// 	lifecycles := doc.Lifecycles()
// 	if len(lifecycles) > 0 {
// 		return catalog.ProfFeatScore{
// 			Score: 10.0,
// 			Desc:  "complete",
// 		}
// 	}
// 	return catalog.ProfFeatScore{
// 		Score: 0.0,
// 		Desc:  "add lifecycle phase",
// 	}
// }

// // Component License (SHOULD)
// func NTIACompLicense(doc sbom.Document) catalog.ProfFeatScore {
// 	comps := doc.Components()
// 	if len(comps) == 0 {
// 		return catalog.ProfFeatScore{
// 			Score: 0.0,
// 			Desc:  formulae.NoComponentsNA(),
// 		}
// 	}

// 	have := 0
// 	for _, c := range comps {
// 		licenses := c.GetLicenses()
// 		if len(licenses) > 0 {
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
