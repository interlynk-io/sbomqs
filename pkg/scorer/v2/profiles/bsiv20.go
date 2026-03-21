// Copyright 2026 Interlynk.io
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
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
)

// BSIV20SpecVersion checks that the SBOM format meets BSI v2.0 minimum version requirements.
// CycloneDX >= 1.5, SPDX >= 2.2.1
func BSIV20SpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == "" || ver == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM spec type or version is missing",
		}
	}

	switch spec {
	case string(sbom.SBOMSpecCDX):
		if isVersionAtLeast(ver, "1.5") {
			return catalog.ProfFeatScore{
				Score: 10.0,
				Desc:  fmt.Sprintf("CycloneDX %s meets minimum version 1.5", ver),
			}
		}
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  fmt.Sprintf("CycloneDX %s does not meet minimum version 1.5", ver),
		}

	case string(sbom.SBOMSpecSPDX):
		if isVersionAtLeast(ver, "2.2") {
			return catalog.ProfFeatScore{
				Score: 10.0,
				Desc:  fmt.Sprintf("SPDX-%s meets minimum version 2.2.1", ver),
			}
		}
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  fmt.Sprintf("SPDX-%s does not meet minimum version 2.2.1", ver),
		}
	}

	return catalog.ProfFeatScore{
		Score: 0.0,
		Desc:  fmt.Sprintf("unsupported spec type: %s", spec),
	}
}

/*
REQUIRED FIELD: BSIV20SBOMCreator

BSI 5.2.1: same requirement as v1.1 with a clarification:
URL examples are now "the creator's home page or the project's web page".

Accepted contact sources:
  - Authors email
  - Manufacturer email or URL
  - Supplier email or URL
*/
func BSIV20SBOMCreator(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11SBOMCreator(doc)
}

/*
REQUIRED FIELD: BSIV20SBOMCreationTimestamp

BSI 5.2.1 same requirement as v1.1.
RFC 3339 / ISO 8601 compliant timestamp.
*/
func BSIV20SBOMCreationTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11SBOMCreationTimestamp(doc)
}

/*
REQUIRED FIELD: BSIV20CompCreator

BSI 5.2.2 same requirement as v1.1 with a clarification:
URL examples are now "the creator's home page or the project's web page".

Accepted contact sources per component:
  - Authors email
  - Manufacturer email or URL
  - Supplier email or URL
*/
func BSIV20CompCreator(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompCreator(doc)
}

/*
REQUIRED FIELD: BSIV20CompName

BSI 5.2.2 "Name assigned to the component by its creator.
If no name is assigned this MUST be the actual filename."

v2.0.0 adds a mandatory filename fallback (the check itself is the same:
the field must be non-empty).

SBOM Mappings:
SPDX: PackageName
CDX:  components[].name
*/
func BSIV20CompName(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompName(doc)
}

/*
REQUIRED FIELD: BSIV20CompVersion

BSI 5.2.2 "Identifier used by the creator to specify changes in the component
to a previously created version. [...] If no version is assigned this MUST be
the creation date of the file expressed as full-date according to RFC 3339 section 5.6."

v2.0.0 adds a mandatory date fallback; the field itself must be non-empty.

SBOM Mappings:
SPDX: PackageVersion
CDX:  components[].version
*/
func BSIV20CompVersion(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompVersion(doc)
}

/*
REQUIRED FIELD: BSIV20CompFilename

BSI 5.2.2: "The actual filename of the component (i.e. not its path)."

NOTE: The sbom.GetComponent interface does not yet expose a dedicated filename
field (PackageFileName / equivalent). This check returns N/A until the
interface is extended.

SBOM Mappings:
SPDX: PackageFileName
CDX:  no native field custom properties[bsi:filename]
*/
func BSIV20CompFilename(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM spec is missing",
		}
	}

	switch spec {
	case string(sbom.SBOMSpecCDX):
		return bsiPropertyCheck(doc, "bsi:component:filename", "filename")

	case string(sbom.SBOMSpecSPDX):
		// SPDX section 7.13: PackageFileName is the actual filename of the package.
		comps := doc.Components()
		total := len(comps)
		if total == 0 {
			return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found in SBOM."}
		}

		withFilename := 0
		for _, c := range comps {
			if strings.TrimSpace(c.GetFilename()) != "" {
				withFilename++
			}
		}

		if withFilename == total {
			return catalog.ProfFeatScore{Score: 10.0, Desc: "PackageFileName declared for all components."}
		}

		if withFilename == 0 {
			return catalog.ProfFeatScore{Score: 0.0, Desc: "no components declare PackageFileName."}
		}

		return catalog.ProfFeatScore{
			Score: float64(withFilename) / float64(total) * 10.0,
			Desc:  fmt.Sprintf("%d/%d components declare PackageFileName.", withFilename, total),
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "unknown SBOM spec type; cannot evaluate filename property.",
		Ignore: true,
	}
}

/*
REQUIRED FIELD: BSIV20CompDependencies

BSI 5.2.2 same requirement as v1.1, but v2.0.0 explicitly extends "dependencies"
to also include components *contained* in a component (statically linked, embedded).

The DEPENDS_ON + CONTAINS relationship types cover both.
*/
func BSIV20CompDependencies(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Primary component is missing.",
			Ignore: false,
		}
	}

	rels := doc.GetRelationships()
	if len(rels) == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Dependency information is missing.",
			Ignore: false,
		}
	}

	// Build component map
	componentMap := make(map[string]sbom.GetComponent)
	for _, c := range doc.Components() {
		componentMap[c.GetID()] = c
	}
	componentMap[primary.GetID()] = primary.Component()

	// 1. Validate all relationships reference valid components
	for _, r := range rels {
		// SPDXRef-DOCUMENT is not a component but valid as a DESCRIBES source
		if r.GetType() == "DESCRIBES" {
			continue
		}
		if _, ok := componentMap[r.GetFrom()]; !ok {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Broken dependency: source ref points to undefined component.",
				Ignore: false,
			}
		}
		if _, ok := componentMap[r.GetTo()]; !ok {
			return catalog.ProfFeatScore{
				Score:  0.0,
				Desc:   "Broken dependency: target ref points to undefined component.",
				Ignore: false,
			}
		}
	}

	// 2. Ensure primary declares dependencies
	outgoing := doc.GetOutgoingRelations(primary.GetID())
	if len(outgoing) == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "Primary component does not declare its dependencies.",
			Ignore: false,
		}
	}

	// 3. Recursive traversal — v2.0 follows both DEPENDS_ON and CONTAINS
	visited := make(map[string]bool)
	var dfs func(string)
	dfs = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true
		for _, rel := range doc.GetOutgoingRelations(id) {
			if rel.GetType() == "DEPENDS_ON" || rel.GetType() == "CONTAINS" {
				dfs(rel.GetTo())
			}
		}
	}
	dfs(primary.GetID())

	// 4. Ensure no orphan components
	orphanCount := 0
	for id := range componentMap {
		if !visited[id] {
			orphanCount++
		}
	}
	if orphanCount > 0 {
		return catalog.ProfFeatScore{
			Score:  5.0,
			Desc:   fmt.Sprintf("Dependency graph incomplete: %d orphan component(s) found.", orphanCount),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "Dependencies are recursively declared and structurally complete.",
		Ignore: false,
	}
}

/*
REQUIRED FIELD: BSIV20CompAssociatedLicenses

BSI 5.2.2 "Associated licence(s) of the component from the perspective of the SBOM creator."

v2.0.0 introduces a three-tier licence model:
  - Associated licences (required)  what the licensee can use
  - Concluded licences  (additional) what the licensee has chosen
  - Declared licences   (optional)   what the licensor declared

This check covers the required "Associated licences" tier.
Accepted: valid SPDX ID / expression, LicenseRef-* .
Rejected: NONE, NOASSERTION, empty, free-text without SPDX format.

SBOM Mappings:
SPDX: PackageLicenseConcluded (preferred) / PackageLicenseDeclared (fallback)
CDX:  components[].licenses[].license.id / .expression
*/
func BSIV20CompAssociatedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompLicenses(doc)
}

/*
REQUIRED FIELD: BSIV20CompDeployableHash

BSI 5.2.2: "Cryptographically secure checksum (hash value) of the deployed/deployable
component (i.e. as a file on a mass storage device)."

SBOM Mappings:
  - CDX:  externalReferences[type=distribution or distribution-intake].hashes[]
  - SPDX: PackageChecksum (component-level checksums)
*/
func BSIV20CompDeployableHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	withData := 0
	for _, c := range comps {
		switch spec {
		case string(sbom.SBOMSpecCDX):
			// CDX: hash must be on a distribution or distribution-intake external reference
			for _, er := range c.ExternalReferences() {
				t := er.GetRefType()
				if t == "distribution" || t == "distribution-intake" {
					for _, h := range er.GetRefHashes() {
						if strings.TrimSpace(h.GetContent()) != "" {
							withData++
							goto nextComp
						}
					}
				}
			}
		case string(sbom.SBOMSpecSPDX):
			// SPDX: PackageChecksum directly on the package
			for _, chk := range c.GetChecksums() {
				if strings.TrimSpace(chk.GetContent()) != "" {
					withData++
					goto nextComp
				}
			}
		}
	nextComp:
	}

	return componentScore(withData, total, "deployable component hash")
}

/*
REQUIRED FIELD: BSIV20CompExecutableProperty

BSI 5.2.2: "Describes whether the component is executable;
possible values are 'executable' and 'non-executable'."

NOTE: The sbom.GetComponent interface does not expose a dedicated
executable-property field. This check returns N/A until the interface
is extended.

SBOM Mappings:
SPDX: PrimaryPackagePurpose = APPLICATION (section 7.12)
CDX:  no dedicated field: custom properties[bsi:executableProperty]
*/
func BSIV20CompExecutableProperty(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM spec is missing",
		}
	}

	switch spec {
	case string(sbom.SBOMSpecCDX):
		return bsiPropertyCheck(doc, "bsi:component:executable", "executable property")

	case string(sbom.SBOMSpecSPDX):
		// SPDX section 7.12: PrimaryPackagePurpose APPLICATION maps to executable.
		return spdxPurposeCheck(doc, "APPLICATION", "executable property")
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "unknown SBOM spec type; cannot evaluate executable property.",
		Ignore: false,
	}
}

/*
REQUIRED FIELD: BSIV20CompArchiveProperty

BSI 5.2.2 "Describes whether the component is an archive;
possible values are 'archive' and 'no archive'."

NOTE: The sbom.GetComponent interface does not expose a dedicated
archive-property field. This check returns N/A until the interface
is extended.

SBOM Mappings:
SPDX: PrimaryPackagePurpose = ARCHIVE (section 7.12)
CDX:  no dedicated field: custom properties[bsi:archiveProperty]
*/
func BSIV20CompArchiveProperty(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM spec is missing",
		}
	}

	switch spec {
	case string(sbom.SBOMSpecCDX):
		return bsiPropertyCheck(doc, "bsi:component:archive", "archive property")

	case string(sbom.SBOMSpecSPDX):
		// SPDX section 7.12: PrimaryPackagePurpose ARCHIVE maps to archive.
		return spdxPurposeCheck(doc, "ARCHIVE", "archive property")
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "unknown SBOM spec type; cannot evaluate archive property.",
		Ignore: false,
	}
}

/*
REQUIRED FIELD: BSIV20CompStructuredProperty

BSI 5.2.2 "Describes whether the component is a structured file;
possible values are 'structured' and 'unstructured'.
If a component contains both structured and unstructured parts the
value 'structured' MUST be used."

NOTE: The sbom.GetComponent interface does not expose a dedicated
structured-property field. This check returns N/A until the interface
is extended.

SBOM Mappings:
SPDX: PrimaryPackagePurpose = SOURCE (section 7.12)
CDX:  no dedicated field: custom properties[bsi:structuredProperty]
*/
func BSIV20CompStructuredProperty(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM spec is missing",
		}
	}

	switch spec {
	case string(sbom.SBOMSpecCDX):
		return bsiPropertyCheck(doc, "bsi:component:structured", "structured property")

	case string(sbom.SBOMSpecSPDX):
		// SPDX section 7.12: PrimaryPackagePurpose SOURCE maps to structured.
		return spdxPurposeCheck(doc, "SOURCE", "structured property")
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "unknown SBOM spec type; cannot evaluate structured property.",
		Ignore: false,
	}
}

// =========================================================
// BSI TR-03183-2 v2.0.0 ADDITIONAL fields (5.3)
// Must be provided if they exist and prerequisites are met.
// =========================================================

/*
ADDITIONAL FIELD: BSIV20SBOMURI

BSI 5.3.1 "Uniform Resource Identifier (URI) of this SBOM."
Same requirement as v1.1.

SBOM Mappings:
SPDX: documentNamespace
CDX:  serialNumber + version
*/
func BSIV20SBOMURI(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11SBOMURI(doc)
}

/*
ADDITIONAL FIELD: BSIV20CompSourceURI

BSI 5.3.2: "URI of the source code of the component, e.g. the URL of the
utilised source code version in its repository, or if a version cannot be
specified the utilised source code repository itself."

v2.0.0 clarifies that a version-specific URL is preferred.

SBOM Mappings:
SPDX: no dedicated native field: ExternalRef category OTHER
CDX:  components[].externalReferences[].type = "vcs" or "source-distribution"
*/
func BSIV20CompSourceURI(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompSourceURI(doc)
}

/*
ADDITIONAL FIELD: BSIV20CompDeployableURI

BSI 5.3.2: "URI which points directly to the deployable (e.g. downloadable)
form of the component."

v2.0.0 renames "executable form" -> "deployable form" to align with the broader
component definition that now includes archives.

SBOM Mappings:
SPDX: PackageDownloadLocation
CDX:  components[].externalReferences[].type = "distribution" or "distribution-intake"
*/
func BSIV20CompDeployableURI(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompExecutableURI(doc)
}

/*
ADDITIONAL FIELD: BSIV20CompOtherIdentifiers

BSI 5.3.2: "Other identifiers that can be used to identify the component
or to look it up in relevant databases, such as CPE or Package URL (purl)."
Same requirement as v1.1.

SBOM Mappings:
SPDX: ExternalRef PACKAGE-MANAGER/purl, SECURITY/cpe22Type or cpe23Type
CDX:  components[].purl, components[].cpe
*/
func BSIV20CompOtherIdentifiers(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompOtherIdentifiers(doc)
}

/*
ADDITIONAL FIELD: BSIV20CompConcludedLicenses

BSI 5.3.2: "The licence(s) that the licensee of the component has concluded
for this component."

Concluded licences are determined by the licensee (the SBOM creator). They
differ from associated licences when a component offers mutually exclusive
licence options (e.g. GPL vs. proprietary). This field records which option
was actually chosen, documenting the downstream obligation.

Accepted: valid SPDX ID / expression, LicenseRef-*.
Rejected: NONE, NOASSERTION, empty.

SBOM Mappings:
SPDX: PackageLicenseConcluded
CDX:  components[].licenses[].acknowledgement = "concluded"
*/
func BSIV20CompConcludedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		// Additional field: prerequisite condition (components exist) is not met.
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components found in SBOM.",
			Ignore: true,
		}
	}

	valid := 0
	presentButInvalid := 0

	for _, c := range comps {
		hasValid := false
		hasAny := false

		for _, l := range c.ConcludedLicenses() {
			hasAny = true
			if isAcceptableLicense(l) {
				hasValid = true
				break
			}
		}

		if hasValid {
			valid++
		} else if hasAny {
			presentButInvalid++
		}
	}

	if valid == total {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "concluded licence declared for all components",
			Ignore: false,
		}
	}

	if valid > 0 {
		return catalog.ProfFeatScore{
			Score:  float64(valid) / float64(total) * 10.0,
			Desc:   fmt.Sprintf("%d/%d components have valid concluded licence", valid, total),
			Ignore: false,
		}
	}

	if presentButInvalid > 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   fmt.Sprintf("%d/%d components have invalid concluded licence", presentButInvalid, total),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "no components declare concluded licence (additional field).",
		Ignore: true,
	}
}

// =========================================================
// BSI TR-03183-2 v2.0.0 OPTIONAL fields (5.4)
// MAY be provided if they exist and prerequisites are met.
// =========================================================

/*
OPTIONAL FIELD: BSIV20CompDeclaredLicenses

BSI 5.4.1: "The licence(s) that the licensor of the component has declared
for this component."

Declared licences are what the component's creator stated. They differ from
associated licences (what the licensee can use) when a choice of licence exists.

Accepted: valid SPDX ID / expression, LicenseRef-*.
Rejected: NONE, NOASSERTION, empty.

SBOM Mappings:
SPDX: PackageLicenseDeclared
CDX:  components[].licenses[].acknowledgement = "declared"
*/
func BSIV20CompDeclaredLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		// Optional field: prerequisite condition (components exist) is not met.
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components found in SBOM.",
			Ignore: true,
		}
	}

	valid := 0
	presentButInvalid := 0

	for _, c := range comps {
		hasValid := false
		hasAny := false

		for _, l := range c.DeclaredLicenses() {
			hasAny = true
			if isAcceptableLicense(l) {
				hasValid = true
				break
			}
		}

		if hasValid {
			valid++
		} else if hasAny {
			presentButInvalid++
		}
	}

	if valid == total {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "declared licence declared for all components",
			Ignore: false,
		}
	}

	if valid > 0 {
		return catalog.ProfFeatScore{
			Score:  float64(valid) / float64(total) * 10.0,
			Desc:   fmt.Sprintf("%d/%d components have valid declared licence", valid, total),
			Ignore: false,
		}
	}

	if presentButInvalid > 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   fmt.Sprintf("%d/%d components have invalid declared licence", presentButInvalid, total),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "no components declare declared licence (optional field).",
		Ignore: true,
	}
}

/*
OPTIONAL FIELD: BSIV20CompSourceHash

BSI 5.4.1: "Cryptographically secure checksum (hash value) of the component
source code. The specific algorithm and method are not yet defined by BSI."

v2.0.0 demotes this from "additional" to "optional" because the hash algorithm
and source-tree calculation method remain unspecified.

SBOM Mappings:
SPDX: PackageVerificationCode (closest available, SHA-1-based)
CDX:  externalReferences[].hashes[] on vcs or source-distribution references
*/
func BSIV20CompSourceHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components found in SBOM.",
			Ignore: true,
		}
	}

	withData := 0
	for _, c := range comps {
		if strings.TrimSpace(c.SourceCodeHash()) != "" {
			withData++
		}
	}

	if withData == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declare source hash (optional field).",
			Ignore: true,
		}
	}

	if withData == total {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "source hash declared for all components.",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  float64(withData) / float64(total) * 10.0,
		Desc:   fmt.Sprintf("%d/%d components declare source hash.", withData, total),
		Ignore: false,
	}
}

// spdxPurposeCheck evaluates a BSI property for SPDX documents by checking whether
// a package's PrimaryPackagePurpose matches the given purpose (case-insensitive).
// A package with a matching purpose is counted as declaring the property.
// Ignore is always false — these are required BSI fields.
func spdxPurposeCheck(doc sbom.Document, purpose, fieldLabel string) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components found in SBOM.",
			Ignore: false,
		}
	}

	target := strings.ToUpper(purpose)
	matched := 0
	for _, c := range comps {
		if strings.ToUpper(strings.TrimSpace(c.PrimaryPurpose())) == target {
			matched++
		}
	}

	if matched == total {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   fmt.Sprintf("%s declared for all components.", fieldLabel),
			Ignore: false,
		}
	}
	if matched == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   fmt.Sprintf("no components declare %s via PrimaryPackagePurpose.", fieldLabel),
			Ignore: false,
		}
	}
	return catalog.ProfFeatScore{
		Score:  float64(matched) / float64(total) * 10.0,
		Desc:   fmt.Sprintf("%d/%d components declare %s via PrimaryPackagePurpose.", matched, total, fieldLabel),
		Ignore: false,
	}
}
