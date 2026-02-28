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
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// =========================================================
// BSI TR-03183-2 v2.0.0 — Adapter stubs (legacy names)
// These delegate to common or v1.1 helpers and are kept for
// backward-compatibility with the existing registry entries.
// =========================================================

// sbomWithBomLinksCheck
func BSISBOMWithBomLinks(doc sbom.Document) catalog.ProfFeatScore {
	links := doc.Spec().GetExtDocRef()
	if len(links) == 0 {
		formulae.ScoreSBOMProfNA("no bom links found", true)
	}
	return formulae.ScoreSBOMProfFull("bom links", true)
}

// BSISBOMWithVulnerabilities (BSI v2.0 note: MUST NOT contain vuln info)
func BSISBOMWithVulnerabilities(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMVulnerabilities(doc)
}

// BSISBOMWithSignature
func BSISBOMWithSignature(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSignature(doc)
}

// BSICompWithAssociatedLicenses: concluded for SPDX, effective for CDX components
func BSICompWithAssociatedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// CompWithConcludedLicensesCheck (SPDX)
func CompWithConcludedLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	return CompConcludedLicenses(doc)
}

// CompWithDeclaredLicensesCheck
func CompWithDeclaredLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	return CompDeclaredLicenses(doc)
}

// BSICompWithLicenses checks Component License
func BSICompWithLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// BSICompWithHash checks Component Hash
func BSICompWithHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompHash(doc)
}

// BSICompWithSourceCodeURI checks Component Source URL
func BSICompWithSourceCodeURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeURL(doc)
}

// BSICompWithDownloadURI checks Component Download URL
func BSICompWithDownloadURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompDownloadCodeURL(doc)
}

// BSICompWithSourceCodeHash checks Component Source Hash
func BSICompWithSourceCodeHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeHash(doc)
}

// BSICompWithDependencies evaluates component-level dependency correctness
// for summary scoring, per BSI TR-03183.
func BSICompWithDependencies(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(false)
	}

	withDeps := lo.Filter(comps, func(c sbom.GetComponent, _ int) bool {
		deps := doc.GetDirectDependencies(
			c.GetID(),
			"DEPENDS_ON",
			"CONTAINS",
		)
		return len(deps) > 0
	})

	if len(withDeps) == 0 {
		return formulae.ScoreProfileCustomNA(false, "no components declare dependencies")
	}

	valid := lo.CountBy(withDeps, func(c sbom.GetComponent) bool {
		deps := doc.GetDirectDependencies(
			c.GetID(),
			"DEPENDS_ON",
			"CONTAINS",
		)
		return len(deps) > 0
	})

	return formulae.ScoreProfFull(valid, len(withDeps), false)
}

// BSISBOMNamespace checks URI/Namespace
func BSISBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMNamespace(doc)
}

// =========================================================
// BSI TR-03183-2 v2.0.0 — REQUIRED fields (§5.2)
// Named BSIV20* for unambiguous versioning.
// =========================================================

/*
REQUIRED FIELD: BSIV20SBOMCreator

BSI §5.2.1 — same requirement as v1.1 with a clarification:
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

BSI §5.2.1 — same requirement as v1.1.
RFC 3339 / ISO 8601 compliant timestamp.
*/
func BSIV20SBOMCreationTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11SBOMCreationTimestamp(doc)
}

/*
REQUIRED FIELD: BSIV20CompCreator

BSI §5.2.2 — same requirement as v1.1 with a clarification:
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

BSI §5.2.2 — "Name assigned to the component by its creator.
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

BSI §5.2.2 — "Identifier used by the creator to specify changes in the component
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

BSI §5.2.2 — "The actual filename of the component (i.e. not its path)."

NOTE: The sbom.GetComponent interface does not yet expose a dedicated filename
field (PackageFileName / equivalent). This check returns N/A until the
interface is extended.

SBOM Mappings:
SPDX: PackageFileName
CDX:  no native field — custom properties[bsi:filename]
*/
func BSIV20CompFilename(doc sbom.Document) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "component filename check not yet supported by the SBOM interface",
		Ignore: true,
	}
}

/*
REQUIRED FIELD: BSIV20CompDependencies

BSI §5.2.2 — same requirement as v1.1, but v2.0.0 explicitly extends "dependencies"
to also include components *contained* in a component (statically linked, embedded).

The DEPENDS_ON + CONTAINS relationship types cover both.
*/
func BSIV20CompDependencies(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompDependencies(doc)
}

/*
REQUIRED FIELD: BSIV20CompAssociatedLicenses

BSI §5.2.2 — "Associated licence(s) of the component from the perspective of the SBOM creator."

v2.0.0 introduces a three-tier licence model:
  - Associated licences (required)  — what the licensee can use
  - Concluded licences  (additional) — what the licensee has chosen
  - Declared licences   (optional)   — what the licensor declared

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

BSI §5.2.2 — "Cryptographically secure checksum (hash value) of the deployed/deployable
component (i.e. as a file on a mass storage device) as SHA-512."

KEY CHANGE vs v1.1:
  - v1.1 required SHA-256 of the "executable" component.
  - v2.0.0 requires SHA-512 of the "deployable" component.
  - "Deployable" broadens scope to executables, archives, and other delivered files.

Accepted hash:
  - SHA-512 ONLY.  SHA-256, SHA-1, MD5, and all other algorithms do NOT satisfy this.

SBOM Mappings:
SPDX: PackageChecksum with algorithm SHA512
CDX:  components[].hashes[].alg = "SHA-512"
*/
func BSIV20CompDeployableHash(doc sbom.Document) catalog.ProfFeatScore {
	primary := doc.PrimaryComp()
	if primary == nil {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "primary deployable component is missing.",
			Ignore: false,
		}
	}

	for _, comp := range doc.Components() {
		if comp.GetID() != primary.GetID() {
			continue
		}

		for _, checksum := range comp.GetChecksums() {
			algo := common.NormalizeAlgoName(checksum.GetAlgo())
			value := strings.TrimSpace(checksum.GetContent())

			if algo == "SHA512" && value != "" {
				return catalog.ProfFeatScore{
					Score:  10.0,
					Desc:   "primary deployable component declares a valid SHA-512 hash.",
					Ignore: false,
				}
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "primary deployable component must declare a SHA-512 hash.",
		Ignore: false,
	}
}

/*
REQUIRED FIELD: BSIV20CompExecutableProperty

BSI §5.2.2 — "Describes whether the component is executable;
possible values are 'executable' and 'non-executable'."

NOTE: The sbom.GetComponent interface does not expose a dedicated
executable-property field. This check returns N/A until the interface
is extended.

SBOM Mappings:
SPDX: no dedicated field — ExternalRef category OTHER
CDX:  no dedicated field — custom properties[bsi:executableProperty]
*/
func BSIV20CompExecutableProperty(doc sbom.Document) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "component executable property check not yet supported by the SBOM interface",
		Ignore: true,
	}
}

/*
REQUIRED FIELD: BSIV20CompArchiveProperty

BSI §5.2.2 — "Describes whether the component is an archive;
possible values are 'archive' and 'no archive'."

NOTE: The sbom.GetComponent interface does not expose a dedicated
archive-property field. This check returns N/A until the interface
is extended.

SBOM Mappings:
SPDX: no dedicated field — ExternalRef category OTHER
CDX:  no dedicated field — custom properties[bsi:archiveProperty]
*/
func BSIV20CompArchiveProperty(doc sbom.Document) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "component archive property check not yet supported by the SBOM interface",
		Ignore: true,
	}
}

/*
REQUIRED FIELD: BSIV20CompStructuredProperty

BSI §5.2.2 — "Describes whether the component is a structured file;
possible values are 'structured' and 'unstructured'.
If a component contains both structured and unstructured parts the
value 'structured' MUST be used."

NOTE: The sbom.GetComponent interface does not expose a dedicated
structured-property field. This check returns N/A until the interface
is extended.

SBOM Mappings:
SPDX: no dedicated field — ExternalRef category OTHER
CDX:  no dedicated field — custom properties[bsi:structuredProperty]
*/
func BSIV20CompStructuredProperty(doc sbom.Document) catalog.ProfFeatScore {
	return catalog.ProfFeatScore{
		Score:  0.0,
		Desc:   "component structured property check not yet supported by the SBOM interface",
		Ignore: true,
	}
}

// =========================================================
// BSI TR-03183-2 v2.0.0 — ADDITIONAL fields (§5.3)
// Must be provided if they exist and prerequisites are met.
// =========================================================

/*
ADDITIONAL FIELD: BSIV20SBOMURI

BSI §5.3.1 — "Uniform Resource Identifier (URI) of this SBOM."
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

BSI §5.3.2 — "URI of the source code of the component, e.g. the URL of the
utilised source code version in its repository, or if a version cannot be
specified the utilised source code repository itself."

v2.0.0 clarifies that a version-specific URL is preferred.

SBOM Mappings:
SPDX: no dedicated native field — ExternalRef category OTHER
CDX:  components[].externalReferences[].type = "vcs" or "source-distribution"
*/
func BSIV20CompSourceURI(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompSourceURI(doc)
}

/*
ADDITIONAL FIELD: BSIV20CompDeployableURI

BSI §5.3.2 — "URI which points directly to the deployable (e.g. downloadable)
form of the component."

v2.0.0 renames "executable form" → "deployable form" to align with the broader
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

BSI §5.3.2 — "Other identifiers that can be used to identify the component
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

BSI §5.3.2 — "The licence(s) that the licensee of the component has concluded
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
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "No components found in SBOM.",
			Ignore: false,
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
// BSI TR-03183-2 v2.0.0 — OPTIONAL fields (§5.4)
// MAY be provided if they exist and prerequisites are met.
// =========================================================

/*
OPTIONAL FIELD: BSIV20CompDeclaredLicenses

BSI §5.4.1 — "The licence(s) that the licensor of the component has declared
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
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "No components found in SBOM.",
			Ignore: false,
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

BSI §5.4.1 — "Cryptographically secure checksum (hash value) of the component
source code. The specific algorithm and method are not yet defined by BSI."

v2.0.0 demotes this from "additional" to "optional" because the hash algorithm
and source-tree calculation method remain unspecified.

SBOM Mappings:
SPDX: PackageVerificationCode (closest available, SHA-1-based)
CDX:  externalReferences[].hashes[] on vcs or source-distribution references
*/
func BSIV20CompSourceHash(doc sbom.Document) catalog.ProfFeatScore {
	return BSIV11CompSourceHash(doc)
}
