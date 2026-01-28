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
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	commonV2 "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/interlynk-io/sbomqs/v2/pkg/swid"
	"github.com/samber/lo"
)

// FSCTSBOMAuthors
// FSCT says
// - The Author Name is intended to be the name of the entity (e.g., person or organization but not the tool) that created the SBOM data.
//
// Mappings:
// - For SPDX: CreationInfo.Creators of type "Person" or "Organization"
// - For CycloneDX: metadata.authors
//
// Attributes:
// FSCT does not mandate a specific author atrributes format, so we are considering any of the following info as valid author info:
// - Name
// - Email
// - Website/URL
// - Contact(phone)
//
// Notes:
// - Contact information may be used when a legal entity name is not available.
// - Tools may be declared separately but do not satisfy the Author requirement
func FSCTSBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	total := len(doc.Authors())

	if total == 0 {
		return formulae.ScoreSBOMProfMissingNA("authors", false)
	}

	identified := 0
	contactOnly := 0

	for _, author := range doc.Authors() {
		name := strings.TrimSpace(author.GetName())
		email := strings.TrimSpace(author.GetEmail())
		contact := strings.TrimSpace(author.GetPhone())

		// Identified author
		if name != "" || email != "" {
			identified++
			continue
		}

		// Contact-only author (FSCT-allowed but weak)
		if contact != "" {
			contactOnly++
		}
	}

	if identified > 0 {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "SBOM author entity explicitly identified",
			Ignore: false,
		}
	}

	if contactOnly > 0 {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "SBOM author declared using contact information only",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "add identifiable SBOM author information",
		Ignore: false,
	}
}

// SBOM Timestamp(must)
// FSCT says:
// - The Timestamp is the date and time that the SBOM was produced
//
// Mappings:
// - For SPDX: CreationInfo.Created
// - For CycloneDX: metadata.timestamp
func FSCTSBOMTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM creation timestamp not declared",
			Ignore: false,
		}
	}

	// accept both RFC3339 and RFC3339Nano
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM creation timestamp is not RFC3339 compliant",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "present",
		Ignore: false,
	}
}

// // FSCTSBOMBuildLifecycle checks Build Information
// // optional
// func FSCTSBOMBuildLifecycle(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMLifeCycle(doc)
// }

// FSCTSBOMPrimaryComponent(must)
// FSCT says:
// - The Primary Component, or root of Dependencies, is the subject of the SBOM or the foundational Component being described in the SBOM
//
// Mappings:
// - For SPDX: DocumentDescribes
// - For CycloneDX: metadata.component
func FSCTSBOMPrimaryComponent(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()

	if primary.IsPresent() {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "present",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "add primary component",
		Ignore: false,
	}
}

// FSCTCompName(Must)
// FSCT says:
// - The Component Name is defined as the public name for a Component defined by the Originating Supplier of the Component.
//
// Mappings:
// - For SPDX: PackageName
// - For CycloneDX: components[].name
func FSCTCompName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// FSCTCompVersion(Must)
// FSCT says:
// - The Version is a supplier-defined identifier that specifies an update change in the software from a previously identified version.
//
// Mappings:
// - For SPDX: PackageVersion
// - For CycloneDX: components[].version
func FSCTCompVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// Component Supplier(Must)
// FSCT says:
// - Supplier Name is the entity that creates, defines, and identifies a Component.
// - NOTE: If the upstream supplier is difficult to identify, enter supplier name as unknown.
//
// Mappings:
// - For SPDX: PackageSupplier
// - For CycloneDX: components[].supplier
func FSCTCompSupplier(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	total := len(comps)
	identified := 0
	declaredUnknown := 0

	for _, c := range comps {
		supplier := c.Suppliers()
		if supplier == nil {
			continue
		}

		name := strings.TrimSpace(supplier.GetName())
		url := strings.TrimSpace(supplier.GetURL())
		email := strings.TrimSpace(supplier.GetEmail())

		// Explicitly declared as unknown
		if strings.EqualFold(name, "unknown") {
			declaredUnknown++
			continue
		}

		// Supplier identified
		if name != "" || url != "" || email != "" {
			identified++
		}
	}

	have := identified + declaredUnknown

	desc := "supplier information missing for some components"
	if have == total {
		if declaredUnknown > 0 && identified == 0 {
			desc = "supplier declared as unknown for all components"
		} else if declaredUnknown > 0 {
			desc = "supplier identified for some components; explicitly unknown for others"
		} else {
			desc = "supplier identified for all components"
		}
	} else if have > 0 {
		desc = "supplier declared for some components; missing for others"
	}

	return catalog.ProfFeatScore{
		Score:  formulae.ScoreProfFull(have, total, false).Score,
		Desc:   desc,
		Ignore: false,
	}
}

// Component Unique Identifier (Must)
// FSCT says:
// - Unique identifiers provide additional information to help uniquely define a Component.
// - At least one identifier is required per component.
// - Identifiers may be global or namespace-scoped (e.g., PURL, CPE, SWID, SWHID, UUID).
//
// Note:
// - FSCT does not mandate a specific identifier scheme or require validation
// against external identifier specifications.
func FSCTCompUniqID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return checkFsctUniqueID(c)
	})

	return formulae.ScoreProfFull(have, len(comps), false)
}

// checkFsctUniqueID checks whether the component declares at least one
// unique identifier as expected by FSCT.
func checkFsctUniqueID(c sbom.GetComponent) bool {
	// PURL (do not require full validation)
	for _, p := range c.GetPurls() {
		if strings.TrimSpace(string(p)) != "" {
			return true
		}
	}

	// CPE
	for _, c := range c.GetCpes() {
		if strings.TrimSpace(string(c)) != "" {
			return true
		}
	}

	// SWHID
	for _, id := range c.Swhids() {
		if strings.TrimSpace(string(id)) != "" {
			return true
		}
	}

	// SWID
	for _, id := range c.Swids() {
		if strings.TrimSpace(string(swid.SWID(id).String())) != "" {
			return true
		}
	}

	return false
}

// Component Cryptographic Hash (Must)
// FSCT says:
// - A cryptographic hash is an intrinsic identifier for a software Component.
// - At least one hash may be provided to help verify identity and integrity.
// - If a hash cannot be provided, this should be explicitly stated.
//
// Note:
// FSCT does not mandate a specific hash algorithm or require cryptographic strength.
func FSCTCompChecksum(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.HasAnyChecksum(c)
	})

	return formulae.ScoreProfFull(have, len(comps), false)
}

// Component Dependencies(Must)
// FSCT says:
// - The Primary Component's direct Dependencies must be declared.
// - The completeness of the declared Dependencies must be indicated.
//
// - Relationships declared for the Primary Component
// - Relationships declared for its direct Dependencies
// - Leaf dependencies valid and transitive components mdeps doesn't matter
func FSCTCompDependencies(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return formulae.ScoreProfileCustomNA(false, "define primary component")
	}

	hasUnknown := false

	// --- 1. Check primary component completeness ---
	primaryAgg := DependencyCompleteness(doc, primary.GetID())
	if primaryAgg == sbom.AggregateMissing {
		return formulae.ScoreProfileCustomNA(false, "dependency completeness not declared for primary component")
	}

	if primaryAgg == sbom.AggregateUnknown {
		hasUnknown = true
	}

	// --- 2. Check direct dependencies ---
	primaryDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")

	for _, dep := range primaryDeps {
		depID := dep.GetID()
		agg := DependencyCompleteness(doc, depID)

		if agg == sbom.AggregateMissing {
			return formulae.ScoreProfileCustomNA(
				false,
				fmt.Sprintf("dependency completeness not declared for dependency %s", dep.GetName()),
			)
		}

		if agg == sbom.AggregateUnknown {
			hasUnknown = true
		}
	}

	if hasUnknown {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "relationships declared; completeness explicitly unknown or partial",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "relationships and completeness declared for primary and direct dependencies",
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
