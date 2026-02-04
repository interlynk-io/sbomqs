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
	"sort"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/swid"
	"github.com/samber/lo"
)

// FSCTSBOMProvenance(must)
// - is a combination of both author and timestamp information
//
// FSCT Author says
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
//
// FSCT Timestamp says:
// - The Timestamp is the date and time that the SBOM was produced
//
// Mappings:
// - For SPDX: CreationInfo.Created
// - For CycloneDX: metadata.timestamp
func FSCTSBOMProvenance(doc sbom.Document) catalog.ProfFeatScore {
	// ---------- Timestamp check ----------
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	timestampPresent := true

	if ts == "" {
		timestampPresent = false
	} else {
		if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "SBOM provenance incomplete: creation timestamp present but not RFC3339 compliant; author status evaluated separately",
				Ignore: false,
			}
		}
	}

	// ---------- Author check ----------
	authors := doc.Authors()
	authorIdentified := false
	authorContactOnly := false

	for _, author := range authors {
		name := strings.TrimSpace(author.GetName())
		email := strings.TrimSpace(author.GetEmail())
		phone := strings.TrimSpace(author.GetPhone())

		if name != "" || email != "" {
			authorIdentified = true
			break
		}

		if phone != "" {
			authorContactOnly = true
		}
	}

	authorPresent := authorIdentified || authorContactOnly

	// ---------- Build description ----------
	var parts []string

	if timestampPresent {
		parts = append(parts, "creation timestamp present")
	} else {
		parts = append(parts, "creation timestamp missing")
	}

	if authorIdentified {
		parts = append(parts, "author identified")
	} else if authorContactOnly {
		parts = append(parts, "author declared using contact information only")
	} else {
		parts = append(parts, "author information missing")
	}

	desc := "SBOM provenance: " + strings.Join(parts, "; ")

	// ---------- Final decision ----------
	if timestampPresent && authorPresent {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   desc,
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   desc,
		Ignore: false,
	}
}

// FSCTSBOMPrimaryComponent(must)
// FSCT says:
// - The Primary Component, or root of Dependencies, is the subject of the SBOM or the foundational Component being described in the SBOM
//
// Mappings:
// - For SPDX: DocumentDescribes
// - For CycloneDX: metadata.component
func FSCTSBOMPrimaryComponent(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()

	if !primary.IsPresent() {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM primary component not declared",
			Ignore: false,
		}
	}

	name := strings.TrimSpace(primary.GetName())
	version := strings.TrimSpace(primary.GetVersion())

	if name == "" || version == "" {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "SBOM primary component declared but lacks name or version",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "SBOM subject defined via primary component",
		Ignore: false,
	}
}

func FSCTSBOMRelationships(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "dependency relationships cannot be evaluated: primary component missing",
			Ignore: false,
		}
	}

	// --- 1. Primary component completeness ---
	primaryAgg := DependencyCompleteness(doc, primary.GetID())
	primaryDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")

	if primaryAgg == sbom.AggregateMissing {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"dependency relationships declared (%d), but dependency completeness missing for primary component",
				len(primaryDeps),
			),
			Ignore: false,
		}
	}

	// --- 2. Check completeness for all direct dependencies ---
	totalDeps := len(primaryDeps)
	missingDirectDepsCompleteness := 0

	for _, dep := range primaryDeps {
		agg := DependencyCompleteness(doc, dep.GetID())
		if agg == sbom.AggregateMissing {
			missingDirectDepsCompleteness++
		}
	}

	// --- 3. Baseline decision ---
	if missingDirectDepsCompleteness > 0 {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"dependency relationships declared; completeness missing for %d of %d direct dependencies",
				missingDirectDepsCompleteness, totalDeps,
			),
			Ignore: false,
		}
	}

	// --- 4. Baseline satisfied ---
	var desc string
	if totalDeps == 0 {
		desc = "no dependencies declared; completeness explicitly indicated for primary component"
	} else {
		desc = "dependency relationships and completeness declared for primary component and all direct dependencies"
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   desc,
		Ignore: false,
	}
}

// // SBOM Relationships and Completeness(Must)
// // FSCT says:
// //  - FSCT baseline requires that dependency completeness be declared not only
// //    for the Primary Component, but also for each of its direct dependencies.
// //    This does not mean that all transitive dependencies must be listed.
// //    It means that whenever a component appears in the dependency graph,
// //    the SBOM must explicitly state whether that component’s dependency list is complete, incomplete, or unknown.
// //    Declaring “unknown” is acceptable; failing to declare completeness at all is not.
// //
// // In Short:
// //  - In FSCT baseline, any component that participates in the dependency graph must
// //    declare whether its dependency list is complete — even if that list is empty.

// // - The Primary Component's direct dependencies must be declared.
// // - The completeness of the declared Dependencies must be indicated.
// // - Completeness declaration can be considered as complete, incomplete, or unknown
// // - Only direct Dependencies are required at baseline.
// // - Leaf dependencies valid and transitive components deps doesn't matter
// func FSCTSBOMRelationships(doc sbom.Document) catalog.ProfFeatScore {
// 	primary := doc.PrimaryComp()
// 	if !primary.IsPresent() {
// 		return formulae.ScoreProfileCustomNA(false, "define primary component")
// 	}

// 	// --- 1. Primary Component completeness ---
// 	primaryAgg := DependencyCompleteness(doc, primary.GetID())

// 	// --- 2. Check direct dependencies(may be empty) ---
// 	primaryDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")

// 	if primaryAgg == sbom.AggregateMissing {
// 		return formulae.ScoreProfileCustomNA(false, fmt.Sprintf("dependency relationship(%d), but dependency completeness missing for primary component", len(primaryDeps)))
// 	}

// 	totalDeps := len(primaryDeps)

// 	depsWithMissingCompleteness := 0
// 	depsWithCompleteness := 0

// 	// --- 3. Completeness for each direct dependency
// 	for _, dep := range primaryDeps {
// 		agg := DependencyCompleteness(doc, dep.GetID())

// 		if agg == sbom.AggregateMissing {
// 			depsWithMissingCompleteness++
// 		} else {
// 			depsWithCompleteness++
// 		}
// 	}

// 	// --- 4. Description (explain intent clearly) ---

// 	var desc string

// 	if totalDeps == 0 {
// 		desc = "no dependencies declared; completeness explicitly indicated for primary component"
// 	} else if depsWithCompleteness == totalDeps {
// 		desc = "dependency relationships and completeness declared for primary and all direct dependencies"
// 	} else if depsWithCompleteness > 0 {
// 		desc = fmt.Sprintf("dependency relationships declared; completeness declared for primary and %d direct dependencies; missing for %d direct dependencies", depsWithCompleteness, depsWithMissingCompleteness)
// 	} else {
// 		desc = fmt.Sprintf("dependency relationships declared; completeness declared for primary component; missing for all %d direct dependencies", totalDeps)
// 	}

// 	return catalog.ProfFeatScore{
// 		Score:  10.0,
// 		Desc:   desc,
// 		Ignore: false,
// 	}
// }

func DependencyCompleteness(doc sbom.Document, compID string) sbom.CompositionAggregate {
	found := false
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
			found = true
			return c.Aggregate()
		}
	}

	if !found {
		return sbom.AggregateMissing
	}

	return sbom.AggregateUnknown
}

func FSCTCompIdentity(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	missing := 0

	for _, comp := range comps {
		name := strings.TrimSpace(comp.GetName())
		version := strings.TrimSpace(comp.GetVersion())

		if name == "" || version == "" {
			missing++
		}
	}

	if missing > 0 {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"component identity incomplete for %d of %d components",
				missing, total,
			),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "component name and version declared for all components",
		Ignore: false,
	}
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
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	identified := 0
	declaredUnknown := 0
	missing := 0

	for _, comp := range comps {
		supplier := comp.Suppliers()
		if supplier == nil {
			missing++
			continue
		}

		name := strings.TrimSpace(supplier.GetName())
		url := strings.TrimSpace(supplier.GetURL())
		email := strings.TrimSpace(supplier.GetEmail())

		contactIdentified := false
		for _, c := range supplier.GetContacts() {
			if strings.TrimSpace(c.GetName()) != "" || strings.TrimSpace(c.GetEmail()) != "" {
				contactIdentified = true
				break
			}
		}

		// Explicitly declared as unknown
		if strings.EqualFold(name, "unknown") {
			declaredUnknown++
			continue
		}

		// Supplier identified
		if name != "" || url != "" || email != "" || contactIdentified {
			identified++
			continue
		}

		missing++
	}

	// Any missing supplier breaks minimum expectation
	if missing > 0 {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"supplier attribution missing for %d components",
				missing,
			),
			Ignore: false,
		}
	}

	// All components have supplier declared
	if declaredUnknown > 0 && identified == 0 {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "supplier declared as unknown for all components",
			Ignore: false,
		}
	}

	if declaredUnknown > 0 {
		return catalog.ProfFeatScore{
			Score: 10.0,
			Desc: fmt.Sprintf(
				"supplier identified for %d components; explicitly unknown for %d",
				identified, declaredUnknown,
			),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "supplier identified for all components",
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
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	have := 0

	var (
		purlSeen    bool
		cpeSeen     bool
		swhidSeen   bool
		swidSeen    bool
		omniborSeen bool
	)

	for _, c := range comps {
		t := detectFsctUniqueIDTypes(c)

		if t.purl || t.cpe || t.swhid || t.swid || t.omnibor {
			have++
		}

		purlSeen = purlSeen || t.purl
		cpeSeen = cpeSeen || t.cpe
		swhidSeen = swhidSeen || t.swhid
		swidSeen = swidSeen || t.swid
		omniborSeen = omniborSeen || t.omnibor
	}

	// Any missing unique identifier breaks minimum expectation
	if have != total {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"unique identifier missing for %d components",
				total-have,
			),
			Ignore: false,
		}
	}

	// Build identifier kind list (quality signal)
	var kinds []string
	if purlSeen {
		kinds = append(kinds, "PURL")
	}
	if cpeSeen {
		kinds = append(kinds, "CPE")
	}
	if swhidSeen {
		kinds = append(kinds, "SWHID")
	}
	if swidSeen {
		kinds = append(kinds, "SWID")
	}
	if omniborSeen {
		kinds = append(kinds, "OmniBOR")
	}

	desc := "unique identifier declared for all components"
	if len(kinds) > 0 {
		desc = fmt.Sprintf(
			"unique identifier declared for all components (%s)",
			strings.Join(kinds, ", "),
		)
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   desc,
		Ignore: false,
	}
}

type uniqIDTypes struct {
	purl    bool
	cpe     bool
	swhid   bool
	swid    bool
	omnibor bool
}

func detectFsctUniqueIDTypes(c sbom.GetComponent) uniqIDTypes {
	var t uniqIDTypes

	for _, p := range c.GetPurls() {
		if strings.TrimSpace(string(p)) != "" {
			t.purl = true
		}
	}
	for _, cpe := range c.GetCpes() {
		if strings.TrimSpace(string(cpe)) != "" {
			t.cpe = true
		}
	}
	for _, id := range c.Swhids() {
		if strings.TrimSpace(string(id)) != "" {
			t.swhid = true
		}
	}
	for _, id := range c.Swids() {
		if strings.TrimSpace(string(swid.SWID(id).String())) != "" {
			t.swid = true
		}
	}
	for _, id := range c.OmniborIDs() {
		if strings.TrimSpace(string(id)) != "" {
			t.omnibor = true
		}
	}

	return t
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
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	have := 0
	algoSeen := make(map[string]bool)

	for _, c := range comps {
		k := detectFsctChecksumKinds(c)

		if len(k.weak) > 0 || len(k.strong) > 0 {
			have++
		}

		for a := range k.weak {
			algoSeen[a] = true
		}
		for a := range k.strong {
			algoSeen[a] = true
		}
	}

	// Any missing checksum breaks minimum expectation
	if have != total {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc: fmt.Sprintf(
				"cryptographic hash missing for %d components",
				total-have,
			),
			Ignore: false,
		}
	}

	// Build algorithm list for description (quality signal)
	var algos []string
	for a := range algoSeen {
		algos = append(algos, a)
	}
	sort.Strings(algos)

	desc := "cryptographic hash declared for all components"
	if len(algos) > 0 {
		desc = fmt.Sprintf(
			"cryptographic hash declared for all components (%s)",
			strings.Join(algos, ", "),
		)
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   desc,
		Ignore: false,
	}
}

type checksumKinds struct {
	weak   map[string]bool
	strong map[string]bool
}

func detectFsctChecksumKinds(c sbom.GetComponent) checksumKinds {
	k := checksumKinds{
		weak:   make(map[string]bool),
		strong: make(map[string]bool),
	}

	for _, cs := range c.GetChecksums() {
		algo := common.NormalizeAlgoName(cs.GetAlgo())
		content := strings.TrimSpace(cs.GetContent())
		if content == "" {
			continue
		}

		if common.IsWeakChecksum(algo) {
			k.weak[algo] = true
		} else if common.IsStrongChecksum(algo) {
			k.strong[algo] = true
		}
	}

	return k
}

// Component License (Must)
// FSCT says:
// - License information identifies the legal terms under which a Component may be used.
// - Each Component should declare its concluded license.
// - If the license cannot be determined, it should be explicitly stated.
//
// Notes:
// - FSCT does not require SPDX license identifiers.
// - FSCT does not require license validation.
// - Presence and transparency are the goal.
func FSCTCompLicense(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "license coverage cannot be evaluated: primary component missing",
			Ignore: false,
		}
	}

	// Count license presence across all components
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return common.ComponentHasAnyLicense(c)
	})

	for _, c := range comps {
		if c.GetID() == primary.GetID() {
			if !common.ComponentHasAnyLicense(c) {
				desc := "license missing for primary component (minimum expectation not met) and all components"
				if have > 0 {
					desc = fmt.Sprintf(
						"license missing for primary component (minimum expectation not met); "+
							"license present for %d components",
						have,
					)
				}

				return catalog.ProfFeatScore{
					Score:  0.0,
					Desc:   desc,
					Ignore: false,
				}
			}
		}
	}

	desc := "license declared only for primary component (minimum coverage)"

	if have == total {
		desc = "license declared for all components (full coverage: aspirational)"
	} else if have > 1 {
		desc = fmt.Sprintf(
			"license declared for %d of %d components (partial coverage: recommended)",
			have, total,
		)
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   desc,
		Ignore: false,
	}
}

// Component Copyright (Must)
// FSCT says:
// - Copyright identifies the legal ownership of a Component.
// - Each Component should declare copyright information.
// - If the copyright holder cannot be determined, this should be explicitly stated.
//
// Notes:
// - FSCT does not mandate a specific format.
// - FSCT does not require validation or legal correctness.
// - Presence and transparency are the goal.
func FSCTCompCopyright(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declared in SBOM",
			Ignore: false,
		}
	}

	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "copyright coverage cannot be evaluated: primary component missing",
			Ignore: false,
		}
	}

	// Count copyright presence across all components
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		val := strings.ToLower(strings.TrimSpace(c.GetCopyRight()))
		return val != "" && val != "none" && val != "noassertion"
	})

	for _, c := range comps {
		if c.GetID() == primary.GetID() {

			// ----- Minimum expectation: primary component must have copyright -----
			primaryVal := strings.ToLower(strings.TrimSpace(c.GetCopyRight()))
			if primaryVal == "" || primaryVal == "none" || primaryVal == "noassertion" {

				desc := "copyright missing for primary component (minimum expectation not met) and all components"
				if have > 0 {
					desc = fmt.Sprintf(
						"copyright missing for primary component (minimum expectation not met); "+
							"copyright present for %d components",
						have,
					)
				}

				return catalog.ProfFeatScore{
					Score:  0.0,
					Desc:   desc,
					Ignore: false,
				}
			}
		}
	}

	// ----- Coverage evaluation (minimum satisfied) -----
	desc := "copyright declared only for primary component (minimum coverage)"

	if have == total {
		desc = "copyright declared for all components (full coverage: aspirational)"
	} else if have > 1 {
		desc = fmt.Sprintf(
			"copyright declared for %d of %d components (partial coverage: recommended)",
			have, total,
		)
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   desc,
		Ignore: false,
	}
}
