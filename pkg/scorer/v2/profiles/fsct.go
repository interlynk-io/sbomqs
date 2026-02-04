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
		Desc:   "add authors",
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
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
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

// SBOM Relationships and Completeness(Must)
// FSCT says:
//  - FSCT baseline requires that dependency completeness be declared not only
//    for the Primary Component, but also for each of its direct dependencies.
//    This does not mean that all transitive dependencies must be listed.
//    It means that whenever a component appears in the dependency graph,
//    the SBOM must explicitly state whether that component’s dependency list is complete, incomplete, or unknown.
//    Declaring “unknown” is acceptable; failing to declare completeness at all is not.
//
// In Short:
//  - In FSCT baseline, any component that participates in the dependency graph must
//    declare whether its dependency list is complete — even if that list is empty.

// - The Primary Component's direct dependencies must be declared.
// - The completeness of the declared Dependencies must be indicated.
// - Completeness declaration can be considered as complete, incomplete, or unknown
// - Only direct Dependencies are required at baseline.
// - Leaf dependencies valid and transitive components deps doesn't matter
func FSCTSBOMRelationships(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return formulae.ScoreProfileCustomNA(false, "define primary component")
	}

	// --- 1. Primary Component completeness ---
	primaryAgg := DependencyCompleteness(doc, primary.GetID())

	// --- 2. Check direct dependencies(may be empty) ---
	primaryDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")

	if primaryAgg == sbom.AggregateMissing {
		return formulae.ScoreProfileCustomNA(false, fmt.Sprintf("dependency relationship(%d), but dependency completeness missing for primary component", len(primaryDeps)))
	}

	totalDeps := len(primaryDeps)

	depsWithMissingCompleteness := 0
	depsWithCompleteness := 0

	// --- 3. Completeness for each direct dependency
	for _, dep := range primaryDeps {
		agg := DependencyCompleteness(doc, dep.GetID())

		if agg == sbom.AggregateMissing {
			depsWithMissingCompleteness++
		} else {
			depsWithCompleteness++
		}
	}

	// --- 4. Description (explain intent clearly) ---

	var desc string

	if totalDeps == 0 {
		desc = "no dependencies declared; completeness explicitly indicated for primary component"
	} else if depsWithCompleteness == totalDeps {
		desc = "dependency relationships and completeness declared for primary and all direct dependencies"
	} else if depsWithCompleteness > 0 {
		desc = fmt.Sprintf("dependency relationships declared; completeness declared for primary and %d direct dependencies; missing for %d direct dependencies", depsWithCompleteness, depsWithMissingCompleteness)
	} else {
		desc = fmt.Sprintf("dependency relationships declared; completeness declared for primary component; missing for all %d direct dependencies", totalDeps)
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   desc,
		Ignore: false,
	}
}

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

		var contactName, contactEmail string

		for _, c := range supplier.GetContacts() {
			contactEmail = strings.TrimSpace(c.GetEmail())
			contactName = strings.TrimSpace(c.GetName())
		}

		// Explicitly declared as unknown
		if strings.EqualFold(name, "unknown") {
			declaredUnknown++
			continue
		}

		// Supplier identified
		if name != "" || url != "" || email != "" || contactEmail != "" || contactName != "" {
			identified++
		}
	}

	have := identified + declaredUnknown

	desc := fmt.Sprintf("supplier information missing for all(%d) components", total)
	if have == total {
		if declaredUnknown > 0 && identified == 0 {
			desc = "supplier declared as unknown for all components"
		} else if declaredUnknown > 0 {
			desc = fmt.Sprintf("supplier identified for %d components; explicitly unknown for %d", identified, declaredUnknown)
		} else {
			desc = "supplier identified for all components"
		}
	} else if have > 0 {
		desc = fmt.Sprintf("supplier declared for %d components; missing for %d", have, total-have)
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

	var (
		have        int
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

	// Build identifier kind list (for explainability)
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
		kinds = append(kinds, "OmniborID")
	}

	// Description (supplier-style)
	desc := fmt.Sprintf(
		"unique identifier missing for all(%d) components",
		len(comps),
	)

	if have == len(comps) {
		desc = fmt.Sprintf(
			"unique identifier declared for all components (%s)",
			strings.Join(kinds, ", "),
		)
	} else if have > 0 {
		desc = fmt.Sprintf(
			"unique identifier declared for %d components; missing for %d (%s)",
			have,
			len(comps)-have,
			strings.Join(kinds, ", "),
		)
	}

	score := formulae.ScoreProfFull(have, len(comps), false)

	return catalog.ProfFeatScore{
		Score:  score.Score,
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
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	total := len(comps)
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

	// Build algorithm list for description
	var algos []string
	for a := range algoSeen {
		algos = append(algos, a)
	}
	sort.Strings(algos)

	desc := fmt.Sprintf(
		"cryptographic hash missing for all(%d) components",
		total,
	)

	if have == total {
		desc = fmt.Sprintf(
			"cryptographic hash declared for all components (%s)",
			strings.Join(algos, ", "),
		)
	} else if have > 0 {
		desc = fmt.Sprintf(
			"cryptographic hash declared for %d components; missing for %d (%s)",
			have,
			total-have,
			strings.Join(algos, ", "),
		)
	}

	score := formulae.ScoreProfFull(have, total, false)

	return catalog.ProfFeatScore{
		Score:  score.Score,
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
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	total := len(comps)
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return common.ComponentHasAnyConcluded(c)
	})

	desc := fmt.Sprintf(
		"license missing for all(%d) components",
		total,
	)

	if have == total {
		desc = "license declared for all components"
	} else if have > 0 {
		desc = fmt.Sprintf(
			"license declared for %d components; missing for %d",
			have,
			total-have,
		)
	}

	score := formulae.ScoreProfFull(have, total, false)

	return catalog.ProfFeatScore{
		Score:  score.Score,
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
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	total := len(comps)
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		val := strings.ToLower(strings.TrimSpace(c.GetCopyRight()))
		return val != "" && val != "none" && val != "noassertion"
	})

	desc := fmt.Sprintf(
		"copyright missing for all(%d) components",
		total,
	)

	if have == total {
		desc = "copyright declared for all components"
	} else if have > 0 {
		desc = fmt.Sprintf(
			"copyright declared for %d components; missing for %d",
			have,
			total-have,
		)
	}

	score := formulae.ScoreProfFull(have, total, false)

	return catalog.ProfFeatScore{
		Score:  score.Score,
		Desc:   desc,
		Ignore: false,
	}
}
