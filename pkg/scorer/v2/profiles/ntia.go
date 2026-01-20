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

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
)

// Automation Support
func SBOMWithAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAutomationSpec(doc)
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
	directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
	if len(directDeps) > 0 {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "direct dependencies declared for primary component",
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
				Desc:   "primary component declares no dependencies (complete)",
				Ignore: false,
			}

		case sbom.AggregateUnknown:
			return catalog.ProfFeatScore{
				Score:  10.0,
				Desc:   "dependency completeness declared unknown",
				Ignore: false,
			}

		case sbom.AggregateIncomplete:
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "dependency data declared incomplete",
				Ignore: false,
			}
		}
	}

	// 3. No dependencies and no completeness declaration
	// Default interpretation per NTIA: incomplete
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "no dependency relationships declared",
		Ignore: false,
	}

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
