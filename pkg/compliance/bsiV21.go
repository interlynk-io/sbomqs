// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compliance

import (
	"context"
	"fmt"
	"strings"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

var (
	// BSI v2.1 requires CycloneDX >= 1.6, SPDX >= 3.0.1 (SPDX v2 not allowed)
	validBsiV21CdxVersions = []string{"1.6"}
)

func bsiV21Result(ctx context.Context, doc sbom.Document, fileName string, outFormat string) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.bsiV21Result()")

	dtb := db.NewDB()

	// SBOM-level checks
	dtb.AddRecord(bsiV21Vulnerabilities(doc))
	// dtb.AddRecord(bsiSpec(doc))
	dtb.AddRecord(bsiV21SpecVersion(doc))
	// dtb.AddRecord(bsiBuildPhase(doc))
	dtb.AddRecord(bsiV11SBOMCreator(doc))
	dtb.AddRecord(bsiV11SBOMTimestamp(doc))
	dtb.AddRecord(bsiV21SBOMDepth(doc))
	dtb.AddRecord(bsiV21SBOMURI(doc))
	dtb.AddRecord(bsiV21SbomLinks(doc))

	// Component-level checks
	dtb.AddRecords(bsiV21Components(doc))

	if outFormat == pkgcommon.FormatJSON {
		bsiV21JSONReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportBasic {
		bsiV21BasicReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportDetailed {
		bsiV21DetailedReport(dtb, fileName)
	}
}

// bsiV21SpecVersion checks that the SBOM format meets BSI v2.1 minimum version requirements.
// CycloneDX >= 1.6, SPDX v2 is NOT allowed (requires >= 3.0.1).
func bsiV21SpecVersion(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	result, score := "", 0.0

	if spec == string(sbom.SBOMSpecSPDX) {
		// BSI v2.1 requires SPDX >= 3.0.1, SPDX v2.x is NOT allowed
		if bsiV21SpdxVersionAtLeast(version) {
			result = version
			score = 10.0
		} else {
			result = version + " (SPDX v2 not allowed by BSI v2.1)"
			score = 0.0
		}
	} else if spec == string(sbom.SBOMSpecCDX) {
		if bsiV21CdxVersionAtLeast(version) {
			result = version
			score = 10.0
		} else {
			result = version + " (requires >= 1.6)"
			score = 0.0
		}
	}

	return db.NewRecordStmt(SBOM_SPEC_VERSION, "doc", result, score, "")
}

// bsiV21SpdxVersionAtLeast checks if an SPDX version is >= 3.0.1 (BSI v2.1 requirement)
func bsiV21SpdxVersionAtLeast(version string) bool {
	// Normalize version string (remove "SPDX-" prefix if present)
	version = strings.TrimPrefix(version, "SPDX-")
	version = strings.TrimSpace(version)

	// Check if version starts with "3." (3.0, 3.0.1, 3.1, etc.)
	// BSI v2.1 requires SPDX >= 3.0.1
	if strings.HasPrefix(version, "3.") {
		return true
	}
	return false
}

// bsiV21CdxVersionAtLeast checks if a CDX version is >= 1.6.
func bsiV21CdxVersionAtLeast(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	var major, minor int
	if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
		return false
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
		return false
	}

	if major > 1 {
		return true
	}
	return major == 1 && minor >= 6
}

// bsiV21SBOMURI checks for the SBOM-URI field. In v2.1 this is an additional (§5.3) field.
// CDX 1.6: serialNumber or metadata.component.bom-ref. SPDX 3.0 not implemented.
func bsiV21SBOMURI(doc sbom.Document) *db.Record {
	candidate := strings.TrimSpace(doc.Spec().GetURI())

	if candidate == "" {
		return db.NewRecordStmtAdditional(SBOM_URI, "doc", "", 0.0, true)
	}

	if !bsiIsValidURL(candidate) && !strings.HasPrefix(candidate, "urn:") {
		return db.NewRecordStmtAdditional(SBOM_URI, "doc", candidate, 0.0, false)
	}

	result := strings.Join(breakLongString(candidate, 80), "\n")
	return db.NewRecordStmtAdditional(SBOM_URI, "doc", result, 10.0, false)
}

// bsiV21SbomLinks checks for references to another BOM (optional, §8.1.12).
// CDX: externalReferences[type=Bom].
// SPDX 3.0: SpdxDocument.externalRef[].locator referencing other SBOMs.
func bsiV21SbomLinks(doc sbom.Document) *db.Record {
	bom := doc.Spec().GetExtDocRef()
	if bom != nil {
		result := strings.Join(bom, ", ")
		return db.NewRecordStmtOptional(SBOM_BOM_LINKS, "doc", result, 10.0)
	}
	return db.NewRecordStmtOptional(SBOM_BOM_LINKS, "doc", "", 0.0)
}

// bsiV21Vulnerabilities checks that the SBOM does NOT contain vulnerability info.
// BSI v2.1 section 3.1: SBOM MUST NOT contain vulnerability information.
func bsiV21Vulnerabilities(doc sbom.Document) *db.Record {
	result, score := "no-vulnerability", 10.0

	vulns := doc.Vulnerabilities()
	allVulnIDs := make([]string, 0, len(vulns))

	for _, v := range vulns {
		if vulnID := v.GetID(); vulnID != "" {
			allVulnIDs = append(allVulnIDs, vulnID)
		}
	}

	if len(allVulnIDs) > 0 {
		result = strings.Join(allVulnIDs, ", ")
		score = 0.0
	}
	return db.NewRecordStmt(SBOM_VULNERABILITIES, "doc", result, score, "")
}

// bsiV21SBOMDepth checks dependency graph completeness at the document level.
// BSI TR-03183-2 v2.1 §5.1: same recursive requirements as v2.0, plus the completeness
// of the dependency enumeration MUST be clearly indicated (§5.2.2 new requirement).
//
// Scoring (document-level, SBOM_DEPTH):
//
//	 0  => no relationships, broken relationships, or primary does not declare deps
//	 5  => graph declared but has orphan (unreachable) components
//	 5  => graph structurally complete but completeness indication missing
//	10  => graph complete and completeness explicitly indicated
func bsiV21SBOMDepth(doc sbom.Document) *db.Record {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", "primary component missing", 0.0, "")
	}

	rels := doc.GetRelationships()
	if len(rels) == 0 {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", "no relationships declared", 0.0, "")
	}

	componentMap := make(map[string]sbom.GetComponent)
	for _, c := range doc.Components() {
		componentMap[c.GetID()] = c
	}
	// Also include files (for SPDX) as they can be dependency targets
	for _, f := range doc.Files() {
		componentMap[f.GetID()] = f
	}
	componentMap[primary.GetID()] = primary.Component()

	for _, r := range rels {
		if strings.EqualFold(r.GetType(), "DESCRIBES") {
			continue
		}
		if _, ok := componentMap[r.GetFrom()]; !ok {
			return db.NewRecordStmt(SBOM_DEPTH, "doc", "broken-dependency: source ref "+r.GetFrom()+" not found", 0.0, "")
		}
		if _, ok := componentMap[r.GetTo()]; !ok {
			return db.NewRecordStmt(SBOM_DEPTH, "doc", "broken-dependency: target ref "+r.GetTo()+" not found", 0.0, "")
		}
	}

	if len(doc.GetOutgoingRelations(primary.GetID())) == 0 {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", "primary component does not declare its dependencies", 0.0, "")
	}

	visited := make(map[string]bool)
	var dfs func(id string)
	dfs = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true
		for _, rel := range doc.GetOutgoingRelations(id) {
			if strings.EqualFold(rel.GetType(), "DEPENDS_ON") || strings.EqualFold(rel.GetType(), "CONTAINS") {
				dfs(rel.GetTo())
			}
		}
	}
	dfs(primary.GetID())

	// Only count components (not files) as orphans.
	// Files are leaf nodes linked via non-dependency relationships
	// (e.g., hasDistributionArtifact) and should not be counted in
	// the dependency graph completeness check.
	orphanCount := 0
	for _, c := range doc.Components() {
		if !visited[c.GetID()] {
			orphanCount++
		}
	}
	if orphanCount > 0 {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", fmt.Sprintf("dependency graph incomplete: %d orphan component(s) found", orphanCount), 5.0, "")
	}

	// v2.1 §5.2.2: completeness of the enumeration MUST be clearly indicated
	hasCompletenessIndication := false

	switch doc.Spec().GetSpecType() {
	case string(sbom.SBOMSpecCDX):
		// CycloneDX: Composition element indicates scope and aggregate
		for _, comp := range doc.Composition() {
			scope := comp.Scope()
			agg := comp.Aggregate()
			if (scope == sbom.ScopeDependencies || scope == sbom.ScopeGlobal) && agg != sbom.AggregateMissing {
				hasCompletenessIndication = true
				break
			}
		}
	case string(sbom.SBOMSpecSPDX):
		// SPDX 3.0: relationship-level completeness field ("complete", "incomplete", "noAssertion")
		// BSI v2.1 requires SPDX >= 3.0.1, so all dependency relationships carry completeness.
		for _, rel := range doc.GetRelationships() {
			if strings.EqualFold(rel.GetType(), "DEPENDS_ON") || strings.EqualFold(rel.GetType(), "CONTAINS") {
				if strings.EqualFold(rel.GetCompleteness(), "complete") || strings.EqualFold(rel.GetCompleteness(), "incomplete") || strings.EqualFold(rel.GetCompleteness(), "noAssertion") {
					hasCompletenessIndication = true
					break
				}
			}
		}
	}

	if !hasCompletenessIndication {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", "dependency graph complete but completeness indication missing (BSI v2.1 §5.2.2 requires explicit indication)", 5.0, "")
	}

	return db.NewRecordStmt(SBOM_DEPTH, "doc", "dependencies recursively declared, structurally complete, and completeness indicated", 10.0, "")
}

func bsiV21Components(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records := append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0, ""))
		return records
	}

	for _, component := range doc.Components() {
		// Required (§5.2.2) component fields
		records = append(records, bsiV11ComponentCreator(component))
		records = append(records, bsiV11ComponentName(component))
		records = append(records, bsiV11ComponentVersion(component))
		records = append(records, bsiV21ComponentFilename(component))
		records = append(records, bsiV21ComponentDependencies(doc, component))
		records = append(records, bsiV21ComponentDistributionLicense(component))
		records = append(records, bsiV21ComponentDeployableHash(component))
		records = append(records, bsiV21ComponentExecutable(component))
		records = append(records, bsiV21ComponentArchive(component))
		records = append(records, bsiV21ComponentStructured(component))

		// Additional (§5.2.4) component fields
		records = append(records, bsiV21ComponentSourceCodeURL(component))
		records = append(records, bsiV21ComponentDownloadURL(component))
		records = append(records, bsiV21ComponentOtherIdentifiers(component))
		records = append(records, bsiV21ComponentOriginalLicenses(component))

		// Optional (§5.2.5) component fields
		records = append(records, bsiV21ComponentEffectiveLicense(component))
		records = append(records, bsiV21ComponentSourceHash(component))
		records = append(records, bsiV21ComponentSecurityTxtURL(component))
	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
}

// bsiV21ComponentFilename checks for the bsi:component:filename property (SHALL).
// CDX: components[].properties[] with name="bsi:component:filename"
// SPDX 3.0: DistributionArtifact().GetFilename() from software_File linked via hasDistributionArtifact.
func bsiV21ComponentFilename(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check CDX-style BSI property
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:filename"))
	if value != "" {
		return db.NewRecordStmt(COMP_FILENAME, id, value, 10.0, "")
	}

	// Check SPDX 3.0 distribution artifact
	if filename := strings.TrimSpace(component.DistributionArtifact().GetFilename()); filename != "" {
		return db.NewRecordStmt(COMP_FILENAME, id, filename, 10.0, "")
	}

	return db.NewRecordStmt(COMP_FILENAME, id, "", 0.0, "")
}

// bsiV21ComponentExecutable checks for the bsi:component:executable property (SHALL).
// SPDX 3.0: checks DistributionArtifact().IsExecutable() from software_additionalPurpose.
func bsiV21ComponentExecutable(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check CDX-style BSI property
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:executable"))
	if value != "" {
		return db.NewRecordStmt(COMP_EXECUTABLE, id, value, 10.0, "")
	}

	// Check SPDX 3.0 distribution artifact
	if component.DistributionArtifact().IsExecutable() {
		return db.NewRecordStmt(COMP_EXECUTABLE, id, component.DistributionArtifact().GetFilename(), 10.0, "")
	}

	return db.NewRecordStmt(COMP_EXECUTABLE, id, "", 0.0, "")
}

// bsiV21ComponentArchive checks for the bsi:component:archive property (SHALL).
// SPDX 3.0: checks DistributionArtifact().IsArchive() from software_additionalPurpose.
func bsiV21ComponentArchive(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check CDX-style BSI property
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:archive"))
	if value != "" {
		return db.NewRecordStmt(COMP_ARCHIVE, id, value, 10.0, "")
	}

	// Check SPDX 3.0 distribution artifact
	if component.DistributionArtifact().IsArchive() {
		return db.NewRecordStmt(COMP_ARCHIVE, id, component.DistributionArtifact().GetFilename(), 10.0, "")
	}

	return db.NewRecordStmt(COMP_ARCHIVE, id, "", 0.0, "")
}

// bsiV21ComponentStructured checks for the bsi:component:structured property (SHALL).
// SPDX 3.0: checks DistributionArtifact().IsStructured() from software_additionalPurpose.
func bsiV21ComponentStructured(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check CDX-style BSI property
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:structured"))
	if value != "" {
		return db.NewRecordStmt(COMP_STRUCTURED, id, value, 10.0, "")
	}

	// Check SPDX 3.0 distribution artifact
	if component.DistributionArtifact().IsStructured() {
		return db.NewRecordStmt(COMP_STRUCTURED, id, component.DistributionArtifact().GetFilename(), 10.0, "")
	}

	return db.NewRecordStmt(COMP_STRUCTURED, id, "", 0.0, "")
}

// bsiV21ComponentDistributionLicense checks for concluded licenses (SHALL).
// BSI v2.1: Distribution licences require acknowledgement="concluded".
func bsiV21ComponentDistributionLicense(component sbom.GetComponent) *db.Record {
	licenses := component.ConcludedLicenses()

	if len(licenses) == 0 {
		return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "not-compliant", 0.0, "")
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "non-compliant", 0.0, "")
	}

	return db.NewRecordStmt(COMP_CONCLUDED_LICENSE, common.UniqueElementID(component), "compliant", 10.0, "")
}

// bsiV21ComponentOriginalLicenses checks for declared licenses (additional, §5.3).
// BSI v2.1: Original licences require acknowledgement="declared".
func bsiV21ComponentOriginalLicenses(component sbom.GetComponent) *db.Record {
	licenses := component.DeclaredLicenses()
	id := common.UniqueElementID(component)

	if len(licenses) == 0 {
		return db.NewRecordStmtAdditional(COMP_DECLARED_LICENSE, id, "", 0.0, true)
	}

	if !common.AreLicensesValid(licenses) {
		return db.NewRecordStmtAdditional(COMP_DECLARED_LICENSE, id, "non-compliant", 0.0, false)
	}

	return db.NewRecordStmtAdditional(COMP_DECLARED_LICENSE, id, "compliant", 10.0, false)
}

// bsiV21ComponentDeployableHash checks for hash via externalReferences with type="distribution" or "distribution-intake" (SHALL).
// SPDX 3.0: hash is on the distribution artifact file (software_File.verifiedUsing).
func bsiV21ComponentDeployableHash(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check 1: external reference hash (CDX, SPDX 2.x)
	for _, er := range component.ExternalReferences() {
		t := er.GetRefType()
		if t == "distribution" || t == "distribution-intake" {
			for _, h := range er.GetRefHashes() {
				content := strings.TrimSpace(h.GetContent())
				algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
				if content != "" && algo == "SHA512" {
					return db.NewRecordStmt(COMP_DEPLOYABLE_HASH, id, algo+": "+content, 10.0, "")
				}
			}
		}
	}

	// Check 2: distribution artifact hash (SPDX 3.0)
	for _, h := range component.DistributionArtifact().GetHashes() {
		content := strings.TrimSpace(h.GetContent())
		algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
		if content != "" && algo == "SHA512" {
			return db.NewRecordStmt(COMP_DEPLOYABLE_HASH, id, algo+": "+content, 10.0, "")
		}
	}

	return db.NewRecordStmt(COMP_DEPLOYABLE_HASH, id, "", 0.0, "")
}

// bsiV21ComponentSourceCodeURL checks for source code URI via externalReferences type="source-distribution" or "vcs" (additional, §5.3).
// CDX 1.6: externalReferences[type=source-distribution|vcs].url
// SPDX 3.0: software_sourceInfo OR software_SoftwareArtifact with externalRef (type SourceArtifact) linked via generates relationship.
func bsiV21ComponentSourceCodeURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// CDX: externalReferences[type=source-distribution|vcs].url
	// Prioritize source-distribution over vcs.
	for _, er := range component.ExternalReferences() {
		t := er.GetRefType()
		if t == "source-distribution" {
			locator := strings.TrimSpace(er.GetRefLocator())
			if locator == "" {
				continue
			}
			if bsiIsValidURL(locator) {
				return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, locator, 10.0, false)
			}
			return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, locator, 0.0, false)
		}
	}
	for _, er := range component.ExternalReferences() {
		t := er.GetRefType()
		if t == "vcs" {
			locator := strings.TrimSpace(er.GetRefLocator())
			if locator == "" {
				continue
			}
			if bsiIsValidURL(locator) {
				return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, locator, 10.0, false)
			}
			return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, locator, 0.0, false)
		}
	}

	// SPDX: GetSourceCodeURL is populated from software_sourceInfo or source artifact externalRef
	if url := strings.TrimSpace(component.GetSourceCodeURL()); url != "" {
		if bsiIsValidURL(url) {
			return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, url, 10.0, false)
		}
		return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, url, 0.0, false)
	}

	return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, "", 0.0, true)
}

// bsiV21ComponentDownloadURL checks for deployable URI via externalReferences type="distribution" or "distribution-intake" (additional, §5.3).
// CDX 1.6: externalReferences[type=distribution|distribution-intake].url
// SPDX 3.0: software_downloadLocation on Package, OR File.externalRef.externalRefType="binaryArtifact" on distribution artifact.
func bsiV21ComponentDownloadURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// CDX: externalReferences[type=distribution|distribution-intake].url
	for _, er := range component.ExternalReferences() {
		t := er.GetRefType()
		if t == "distribution" || t == "distribution-intake" {
			locator := strings.TrimSpace(er.GetRefLocator())
			if locator == "" {
				continue
			}
			if bsiIsValidURL(locator) {
				return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, locator, 10.0, false)
			}
			return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, locator, 0.0, false)
		}
	}

	// SPDX: GetDownloadLocationURL is populated from software_downloadLocation or binaryArtifact externalRef
	if url := strings.TrimSpace(component.GetDownloadLocationURL()); url != "" {
		if bsiIsValidURL(url) {
			return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, url, 10.0, false)
		}
		return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, url, 0.0, false)
	}

	return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, "", 0.0, true)
}

// bsiV21ComponentOtherIdentifiers checks for CPE, SWID, or PURL (additional, §5.3).
func bsiV21ComponentOtherIdentifiers(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check PURLs
	for _, p := range component.GetPurls() {
		v := strings.TrimSpace(string(p))
		if v != "" {
			return db.NewRecordStmtAdditional(COMP_OTHER_UNIQ_IDS, id, "purl: "+v, 10.0, false)
		}
	}

	// Check CPEs
	for _, cpe := range component.GetCpes() {
		v := strings.TrimSpace(string(cpe))
		if v != "" {
			return db.NewRecordStmtAdditional(COMP_OTHER_UNIQ_IDS, id, "cpe: "+v, 10.0, false)
		}
	}

	// Check SWIDs
	for _, s := range component.Swids() {
		if s.GetTagID() != "" {
			return db.NewRecordStmtAdditional(COMP_OTHER_UNIQ_IDS, id, "swid: "+s.GetTagID(), 10.0, false)
		}
	}

	return db.NewRecordStmtAdditional(COMP_OTHER_UNIQ_IDS, id, "", 0.0, true)
}

// bsiV21ComponentEffectiveLicense checks for the effective license (MAY).
// CDX: bsi:component:effectiveLicence property. The BSI property taxonomy spells it
// "effectiveLicence"; TR-03183-2 v2.1.0 (Table 12) spells it "effectiveLicense".
// Both spellings are accepted.
// SPDX 3.0: hasEffectiveLicense relationship (non-standard BSI extension).
func bsiV21ComponentEffectiveLicense(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// SPDX 3.0: check EffectiveLicenses populated from hasEffectiveLicense relationships
	licenses := component.EffectiveLicenses()
	if len(licenses) > 0 {
		if !common.AreLicensesValid(licenses) {
			return db.NewRecordStmtOptional(COMP_EFFECTIVE_LICENSE, id, "non-compliant", 0.0)
		}
		return db.NewRecordStmtOptional(COMP_EFFECTIVE_LICENSE, id, "compliant", 10.0)
	}

	// CDX: bsi:component:effectiveLicence property (both spellings accepted)
	value := strings.TrimSpace(component.GetPropertyValue("bsi:component:effectiveLicence"))
	if value == "" {
		value = strings.TrimSpace(component.GetPropertyValue("bsi:component:effectiveLicense"))
	}

	if value != "" {
		return db.NewRecordStmtOptional(COMP_EFFECTIVE_LICENSE, id, value, 10.0)
	}

	return db.NewRecordStmtOptional(COMP_EFFECTIVE_LICENSE, id, "", 0.0)
}

// bsiV21ComponentSourceHash checks for hash via externalReferences type="source-distribution" or "vcs" (MAY).
// SPDX 3.0: source code hash from software_SoftwareArtifact.verifiedUsing linked via generates relationship.
func bsiV21ComponentSourceHash(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// SPDX 3.0: check SourceCodeHash populated from source artifact verifiedUsing
	hash := strings.TrimSpace(component.SourceCodeHash())
	if hash != "" {
		// hash is stored as "algo: content"; extract algo for validation
		parts := strings.SplitN(hash, ":", 2)
		if len(parts) == 2 {
			algo := strings.ToUpper(strings.TrimSpace(parts[0]))
			if algo == "SHA512" {
				return db.NewRecordStmtOptional(COMP_SOURCE_HASH, id, hash, 10.0)
			}
		} else {
			// No algo prefix (e.g. SPDX 2.x) — backward compat.
			return db.NewRecordStmtOptional(COMP_SOURCE_HASH, id, hash, 10.0)
		}
		// Non-SHA512 with algo prefix — fall through to check CDX external refs.
	}

	// CDX: externalReferences[type=source-distribution or vcs].hashes
	// Prioritize source-distribution over vcs.
	for _, er := range component.ExternalReferences() {
		t := er.GetRefType()
		if t != "source-distribution" {
			continue
		}
		for _, h := range er.GetRefHashes() {
			content := strings.TrimSpace(h.GetContent())
			algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
			if content != "" && algo == "SHA512" {
				return db.NewRecordStmtOptional(COMP_SOURCE_HASH, id, algo+": "+content, 10.0)
			}
		}
	}
	for _, er := range component.ExternalReferences() {
		t := er.GetRefType()
		if t != "vcs" {
			continue
		}
		for _, h := range er.GetRefHashes() {
			content := strings.TrimSpace(h.GetContent())
			algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
			if content != "" && algo == "SHA512" {
				return db.NewRecordStmtOptional(COMP_SOURCE_HASH, id, algo+": "+content, 10.0)
			}
		}
	}

	return db.NewRecordStmtOptional(COMP_SOURCE_HASH, id, "", 0.0)
}

// bsiV21ComponentSecurityTxtURL checks for security.txt URL (MAY).
// CDX: externalReferences[type=rfc-9116].
// SPDX 3.0: externalRef.externalRefType="securityOther".
func bsiV21ComponentSecurityTxtURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	for _, er := range component.ExternalReferences() {
		t := er.GetRefType()
		// CDX uses "rfc-9116", SPDX 3.0 uses "securityOther" for security.txt
		if t == "rfc-9116" || strings.EqualFold(t, "securityOther") {
			locator := strings.TrimSpace(er.GetRefLocator())
			if locator != "" {
				return db.NewRecordStmtOptional(COMP_SECURITY_TXT_URL, id, locator, 10.0)
			}
		}
	}

	return db.NewRecordStmtOptional(COMP_SECURITY_TXT_URL, id, "", 0.0)
}

// bsiV21ComponentDependencies checks that a component's direct dependencies are declared
// and resolvable. BSI TR-03183-2 v2.1 §5.2.2 inherits v2.0 semantics: DEPENDS_ON + CONTAINS.
//
// Scoring (per component):
//
//	 0  => a declared dependency cannot be resolved to a component in the SBOM
//	10  => all declared deps resolve, or component is a leaf (no deps)
func bsiV21ComponentDependencies(doc sbom.Document, component sbom.GetComponent) *db.Record {
	compID := component.GetID()

	componentMap := make(map[string]sbom.GetComponent)
	for _, c := range doc.Components() {
		componentMap[c.GetID()] = c
	}
	// Also include files (for SPDX) as they can be dependency targets
	for _, f := range doc.Files() {
		componentMap[f.GetID()] = f
	}

	var declared []string
	for _, r := range doc.GetOutgoingRelations(compID) {
		if strings.EqualFold(r.GetType(), "DEPENDS_ON") || strings.EqualFold(r.GetType(), "CONTAINS") {
			declared = append(declared, r.GetTo())
		}
	}

	if len(declared) == 0 {
		return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-dependencies (leaf element)", 10.0, "")
	}

	var names []string
	for _, depID := range declared {
		depComp, exists := componentMap[depID]
		if !exists {
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "broken-dependencies ("+depID+" not found in SBOM)", 0.0, "")
		}
		if name := strings.TrimSpace(depComp.GetName()); name != "" {
			names = append(names, name)
		}
	}

	result := "(all dependencies resolved) " + strings.Join(names, ", ")
	return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")
}
