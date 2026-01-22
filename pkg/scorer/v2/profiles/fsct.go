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
	"fmt"
	"slices"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
)

// FSCTSBOMAuthors: SBOM Author(must)
func FSCTSBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

// SBOM Timestamp(must)
func FSCTSBOMTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

// FSCTSBOMBuildLifecycle checks Build Information
// optional
func FSCTSBOMBuildLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMLifeCycle(doc)
}

// FSCTSBOMPrimaryComponent(must)
func FSCTSBOMPrimaryComponent(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMPrimaryComponent(doc)
}

// Component Name(Must)
func FSCTCompName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// Component Version(Must)
func FSCTCompVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// Component Supplier(Must)
func FSCTCompSupplier(doc sbom.Document) catalog.ProfFeatScore {
	return CompSupplier(doc)
}

// Component Other Identifiers(Must)
func FSCTCompUniqID(doc sbom.Document) catalog.ProfFeatScore {
	return CompUniqID(doc)
}

// Component Hash(Must)
func FSCTCompHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompHash(doc)
}

// Component Dependencies(Must)
// - Relationships declared for the Primary Component
// - Relationships declared for its direct Dependencies
// - Leaf dependencies valid and transitive components mdeps doesn't matter
func FSCTCompDependencies(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return formulae.ScoreProfileCustomNA(false, "define primary component")
	}

	// 1. primary must have direct dependencies
	primaryDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")

	// CASE 1: No relationships declared at all
	if len(primaryDeps) == 0 {
		return formulae.ScoreProfileCustomNA(false, "no relationships declared for primary component")
	}

	hasUnknown := false
	// CASE 2: Primary has dependencies
	primaryAgg := DependencyCompleteness(doc, primary.GetID())
	if primaryAgg == sbom.AggregateIncomplete {
		return formulae.ScoreProfileCustomNA(false, "primary dependency completeness declared incomplete")
	}

	if primaryAgg == sbom.AggregateUnknown {
		hasUnknown = true
	}

	// CASE 3: Check direct dependencies of primary
	for _, dep := range primaryDeps {
		depID := dep.GetID()
		deps := doc.GetDirectDependencies(depID, "DEPENDS_ON")
		agg := DependencyCompleteness(doc, depID)

		if len(deps) == 0 {
			switch agg {
			case sbom.AggregateIncomplete:
				return formulae.ScoreProfileCustomNA(false, fmt.Sprintf("dependency %s declared incomplete", dep.GetName()))

			case sbom.AggregateUnknown:
				hasUnknown = true
			}
		}
	}

	if hasUnknown {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "relationships declared; completeness unknown",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "complete relationships for primary and direct dependencies",
		Ignore: false,
	}
}

func DependencyCompleteness(doc sbom.Document, compID string) sbom.CompositionAggregate {
	for _, c := range doc.Composition() {

		// 1. SBOM-level completeness applies to all components
		if c.Scope() == sbom.ScopeGlobal {
			return c.Aggregate()
		}

		// 2. Dependency-scoped completeness
		if c.Scope() != sbom.ScopeDependencies {
			continue
		}

		if slices.Contains(c.Dependencies(), compID) {
			return c.Aggregate()
		}
	}
	return sbom.AggregateUnknown
}

// Component License(Must)
func FSCTCompLicense(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// Component Copyright(Must)
func FSCTCompCopyright(doc sbom.Document) catalog.ProfFeatScore {
	return CompCopyright(doc)
}
