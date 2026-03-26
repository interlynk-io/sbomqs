// Copyright 2026 Interlynk.io
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
	"net/mail"
	"net/url"
	"strings"
	"time"

	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

var (
	validBsiSpdxVersions = []string{"2.3"}
	validSpdxVersion     = []string{"2.1", "2.2", "2.3"}
	validBsiCdxVersions  = []string{"1.4", "1.5", "1.6"}
)

// BSI compliance check identifiers.
// These constants represent different elements and attributes that are evaluated
// for BSI (German Federal Office for Information Security) SBOM compliance.
// Each constant corresponds to a specific requirement in the BSI guidelines.
//
//nolint:revive,stylecheck
const (
	// SBOM document specification identifiers
	SBOM_SPEC = iota
	SBOM_SPDXID
	SBOM_NAME
	SBOM_COMMENT
	SBOM_ORG
	SBOM_TOOL
	SBOM_NAMESPACE
	SBOM_LICENSE
	SBOM_SPEC_VERSION
	SBOM_BUILD
	SBOM_DEPTH
	SBOM_CREATOR
	SBOM_TIMESTAMP
	SBOM_DEPENDENCY_RELATIONSHIP
	SBOM_COMPONENTS
	SBOM_PACKAGES
	SBOM_URI

	// Component-level compliance identifiers
	COMP_CREATOR
	COMP_NAME
	COMP_VERSION
	COMP_HASH
	COMP_SOURCE_CODE_URL
	COMP_DOWNLOAD_URL
	COMP_OTHER_UNIQ_IDS
	COMP_SOURCE_HASH
	COMP_LICENSE
	COMP_DEPTH

	// Package-level compliance identifiers (SPDX specific)
	PACK_SUPPLIER
	PACK_HASH
	PACK_FILE_ANALYZED
	PACK_SPDXID
	PACK_NAME
	PACK_VERSION
	PACK_DOWNLOAD_URL
	PACK_LICENSE_CON
	PACK_LICENSE_DEC
	PACK_COPYRIGHT
	PACK_INFO
	PACK_EXT_REF

	// Format and metadata identifiers
	SBOM_MACHINE_FORMAT
	SBOM_AUTOMATION_TOOL
	SBOM_DEPENDENCY
	SBOM_HUMAN_FORMAT
	SBOM_BUILD_INFO
	SBOM_DELIVERY_TIME
	SBOM_DELIVERY_METHOD
	SBOM_SCOPE
	SBOM_TYPE
	SBOM_VULNERABILITIES
	SBOM_BOM_LINKS

	// License-related identifiers
	COMP_ASSOCIATED_LICENSE
	COMP_CONCLUDED_LICENSE
	COMP_DECLARED_LICENSE

	// Security identifiers
	SBOM_SIGNATURE

	// BSI v2.1 specific component identifiers
	COMP_FILENAME
	COMP_EXECUTABLE
	COMP_ARCHIVE
	COMP_STRUCTURED
	COMP_EFFECTIVE_LICENSE
	COMP_DEPLOYABLE_HASH
	COMP_SECURITY_TXT_URL
)

func bsiResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.bsiResult()")

	dtb := db.NewDB()

	// Required SBOM-level checks
	dtb.AddRecord(bsiV11SBOMCreator(doc))
	dtb.AddRecord(bsiV11SBOMTimestamp(doc))
	dtb.AddRecord(bsiV11SBOMDepth(doc))

	// Additional SBOM-level checks
	dtb.AddRecord(bsiV11SBOMURI(doc))
	dtb.AddRecords(bsiComponents(doc))

	if outFormat == pkgcommon.FormatJSON {
		bsiJSONReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportBasic {
		bsiBasicReport(dtb, fileName)
	}

	if outFormat == pkgcommon.ReportDetailed {
		bsiDetailedReport(dtb, fileName, colorOutput)
	}
}

func bsiIsValidEmail(e string) bool {
	e = strings.TrimSpace(e)
	if e == "" {
		return false
	}
	_, err := mail.ParseAddress(e)
	return err == nil
}

func bsiIsValidURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" {
		return false
	}
	parsed, err := url.ParseRequestURI(u)
	if err != nil {
		return false
	}
	return parsed.Scheme != "" && parsed.Host != ""
}

func bsiV11SBOMCreator(doc sbom.Document) *db.Record {

	// Authors: valid email only
	for _, author := range doc.Authors() {
		if bsiIsValidEmail(author.GetEmail()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", author.GetEmail()+" (author)", 10.0, "")
		}
	}

	// Manufacturer: email -> URL -> contacts email (checked before supplier per BSI spec)
	if m := doc.Manufacturer(); m != nil {
		if bsiIsValidEmail(m.GetEmail()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", m.GetEmail()+" (manufacturer)", 10.0, "")
		}

		if bsiIsValidURL(m.GetURL()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", m.GetURL()+" (manufacturer)", 10.0, "")
		}

		for _, c := range m.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(SBOM_CREATOR, "doc", c.GetEmail()+" (manufacturer contact)", 10.0, "")
			}
		}
	}

	// Supplier: email -> URL -> contacts email (fallback)
	if s := doc.Supplier(); s != nil {
		if bsiIsValidEmail(s.GetEmail()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", s.GetEmail()+" (supplier)", 10.0, "")
		}

		if bsiIsValidURL(s.GetURL()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", s.GetURL()+" (supplier)", 10.0, "")
		}

		for _, c := range s.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(SBOM_CREATOR, "doc", c.GetEmail()+" (supplier contact)", 10.0, "")
			}
		}
	}

	return db.NewRecordStmt(SBOM_CREATOR, "doc", "", 0.0, "")
}

func bsiV11SBOMTimestamp(doc sbom.Document) *db.Record {
	result, score := "", 0.0
	result = strings.TrimSpace(doc.Spec().GetCreationTimestamp())

	if result != "" {
		if _, err := time.Parse(time.RFC3339, result); err == nil {
			score = 10.0
		}
	}
	return db.NewRecordStmt(SBOM_TIMESTAMP, "doc", result, score, "")
}

func bsiV11SBOMURI(doc sbom.Document) *db.Record {
	uri := strings.TrimSpace(doc.Spec().GetURI())

	// No URI => prerequisite not met => N/A (Additional, Ignore=true)
	if uri == "" {
		return db.NewRecordStmtAdditional(SBOM_URI, "doc", "", 0.0, true)
	}

	// URI present but invalid => prerequisite met, fails validation
	if !bsiIsValidURL(uri) && !strings.HasPrefix(uri, "urn:") {
		return db.NewRecordStmtAdditional(SBOM_URI, "doc", uri, 0.0, false)
	}

	result := strings.Join(breakLongString(uri, 80), "\n")
	return db.NewRecordStmtAdditional(SBOM_URI, "doc", result, 10.0, false)
}

func bsiComponents(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records := append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0, ""))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, bsiV11ComponentCreator(component))
		records = append(records, bsiV11ComponentName(component))
		records = append(records, bsiV11ComponentVersion(component))
		records = append(records, bsiV11ComponentDependencies(doc, component))
		records = append(records, bsiV11ComponentLicense(component))
		records = append(records, bsiV11ComponentExecutableHash(doc, component))

		// Additional fields
		records = append(records, bsiV11ComponentSourceCodeURL(component))
		records = append(records, bsiV11ComponentDownloadURL(component))
		records = append(records, bsiV11ComponentSourceHash(component))
		records = append(records, bsiV11ComponentOtherUniqueIdentifiers(component))
	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
}

func bsiV11ComponentCreator(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Authors: valid email only
	for _, a := range component.Authors() {
		if bsiIsValidEmail(a.GetEmail()) {
			return db.NewRecordStmt(COMP_CREATOR, id, a.GetEmail()+" (author)", 10.0, "")
		}
	}

	// Manufacturer: email -> URL -> contacts email (checked before supplier per BSI spec)
	if m := component.Manufacturer(); !m.IsAbsent() {
		if bsiIsValidEmail(m.GetEmail()) {
			return db.NewRecordStmt(COMP_CREATOR, id, m.GetEmail()+" (manufacturer)", 10.0, "")
		}
		if bsiIsValidURL(m.GetURL()) {
			return db.NewRecordStmt(COMP_CREATOR, id, m.GetURL()+" (manufacturer)", 10.0, "")
		}
		for _, c := range m.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(COMP_CREATOR, id, c.GetEmail()+" (manufacturer contact)", 10.0, "")
			}
		}
	}

	// Suppliers: email -> URL -> contacts email (fallback)
	if s := component.Suppliers(); !s.IsAbsent() {
		if bsiIsValidEmail(s.GetEmail()) {
			return db.NewRecordStmt(COMP_CREATOR, id, s.GetEmail()+" (supplier)", 10.0, "")
		}
		if bsiIsValidURL(s.GetURL()) {
			return db.NewRecordStmt(COMP_CREATOR, id, s.GetURL()+" (supplier)", 10.0, "")
		}
		for _, c := range s.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(COMP_CREATOR, id, c.GetEmail()+" (supplier contact)", 10.0, "")
			}
		}
	}

	return db.NewRecordStmt(COMP_CREATOR, id, "", 0.0, "")
}

func bsiV11ComponentName(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.GetName())

	if result != "" {
		return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), "", 0.0, "")
}

func bsiV11ComponentVersion(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.GetVersion())

	if result != "" {
		return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), "", 0.0, "")
}

// bsiV11ComponentDependencies checks that a component's direct dependencies are declared
// and resolvable. BSI TR-03183-2 v1.1 §5.2.2: each component must enumerate its direct
// dependencies. v1.1 covers DEPENDS_ON relationships only.
//
// Scoring (per component):
//   0  — a declared dependency cannot be resolved to a component in the SBOM
//  10  — all declared deps resolve, or component is a leaf (no deps)
func bsiV11ComponentDependencies(doc sbom.Document, component sbom.GetComponent) *db.Record {
	compID := component.GetID()

	componentMap := make(map[string]sbom.GetComponent)
	for _, c := range doc.Components() {
		componentMap[c.GetID()] = c
	}

	var declared []string
	for _, r := range doc.GetOutgoingRelations(compID) {
		if strings.EqualFold(r.GetType(), "DEPENDS_ON") {
			declared = append(declared, r.GetTo())
		}
	}

	// Leaf component: no direct deps declared
	if len(declared) == 0 {
		return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-dependencies (leaf element)", 10.0, "")
	}

	// Validate each declared dep resolves to a known component
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

// bsiV11SBOMDepth checks dependency graph completeness at the document level.
// BSI TR-03183-2 v1.1 §5.1: recursive dependency resolution MUST be performed at the
// SBOM level; all components must be reachable from the primary component.
//
// Scoring (document-level, SBOM_DEPTH):
//   0  — no relationships, broken relationships, or primary does not declare deps
//   5  — graph declared but has orphan (unreachable) components
//  10  — graph is recursively complete with no orphans
func bsiV11SBOMDepth(doc sbom.Document) *db.Record {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", "primary component missing", 0.0, "")
	}

	rels := doc.GetRelationships()
	if len(rels) == 0 {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", "no relationships declared", 0.0, "")
	}

	// Build component map (include primary)
	componentMap := make(map[string]sbom.GetComponent)
	for _, c := range doc.Components() {
		componentMap[c.GetID()] = c
	}
	componentMap[primary.GetID()] = primary.Component()

	// Validate all relationships reference defined components
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

	// Primary must declare its dependencies
	if len(doc.GetOutgoingRelations(primary.GetID())) == 0 {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", "primary component does not declare its dependencies", 0.0, "")
	}

	// Recursive DFS from primary following DEPENDS_ON (v1.1 does not include CONTAINS)
	visited := make(map[string]bool)
	var dfs func(id string)
	dfs = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true
		for _, rel := range doc.GetOutgoingRelations(id) {
			if strings.EqualFold(rel.GetType(), "DEPENDS_ON") {
				dfs(rel.GetTo())
			}
		}
	}
	dfs(primary.GetID())

	// Detect orphan components
	orphanCount := 0
	for id := range componentMap {
		if !visited[id] {
			orphanCount++
		}
	}
	if orphanCount > 0 {
		return db.NewRecordStmt(SBOM_DEPTH, "doc", fmt.Sprintf("dependency graph incomplete: %d orphan component(s) found", orphanCount), 5.0, "")
	}

	return db.NewRecordStmt(SBOM_DEPTH, "doc", "dependencies are recursively declared and structurally complete", 10.0, "")
}

func bsiV11ComponentLicense(component sbom.GetComponent) *db.Record {

	score := 0.0
	result := ""

	var validID string
	var anyID string

	// Check Concluded Licenses
	for _, l := range component.ConcludedLicenses() {

		id := strings.TrimSpace(l.ShortID())
		if id == "" {
			continue
		}

		if anyID == "" {
			anyID = id
		}

		u := strings.ToUpper(id)
		if u == "NONE" || u == "NOASSERTION" {
			continue
		}

		// Accept valid SPDX
		if l.Spdx() {
			validID = id
			break
		}

		// Accept valid LicenseRef-*
		if l.Custom() && strings.HasPrefix(id, "LicenseRef-") {
			validID = id
			break
		}
	}

	// Check Declared Licenses (fallback)
	if validID == "" {
		for _, l := range component.DeclaredLicenses() {

			id := strings.TrimSpace(l.ShortID())
			if id == "" {
				continue
			}

			if anyID == "" {
				anyID = id
			}

			u := strings.ToUpper(id)
			if u == "NONE" || u == "NOASSERTION" {
				continue
			}

			if l.Spdx() {
				validID = id
				break
			}

			if l.Custom() && strings.HasPrefix(id, "LicenseRef-") {
				validID = id
				break
			}
		}
	}

	switch {
	case validID != "":
		score = 10.0
		result = validID + " (compliant)"

	case anyID != "":
		score = 0.0
		result = anyID + " (non-compliant)"

	default:
		score = 0.0
		result = ""
	}

	return db.NewRecordStmt(COMP_LICENSE, common.UniqueElementID(component), result, score, "")
}

func bsiV11ComponentExecutableHash(doc sbom.Document, component sbom.GetComponent) *db.Record {
	result := ""
	score := 0.0
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	switch spec {
	case string(sbom.SBOMSpecCDX):
		// CDX: hash must be on a distribution or distribution-intake external reference
		for _, er := range component.ExternalReferences() {
			t := er.GetRefType()
			if t == "distribution" || t == "distribution-intake" {
				for _, h := range er.GetRefHashes() {
					algo := strings.ToUpper(strings.ReplaceAll(h.GetAlgo(), "-", ""))
					value := strings.TrimSpace(h.GetContent())
					if (algo == "SHA256" || algo == "SHA512") && value != "" {
						result = h.GetAlgo() + ": " + value
						score = 10.0
						goto done
					}
				}
			}
		}
	case string(sbom.SBOMSpecSPDX):
		// SPDX: PackageChecksum directly on the package
		for _, checksum := range component.GetChecksums() {
			algo := strings.ToUpper(strings.ReplaceAll(checksum.GetAlgo(), "-", ""))
			value := strings.TrimSpace(checksum.GetContent())
			if (algo == "SHA256" || algo == "SHA512") && value != "" {
				result = checksum.GetAlgo() + ": " + value
				score = 10.0
				goto done
			}
		}
	}
done:
	return db.NewRecordStmt(COMP_HASH, common.UniqueElementID(component), result, score, "")
}

func bsiV11ComponentSourceCodeURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	result := strings.TrimSpace(component.GetSourceCodeURL())

	if result == "" {
		// No data: prerequisite not met => N/A
		return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, "", 0.0, true)
	}
	if bsiIsValidURL(result) {
		return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, result, 10.0, false)
	}
	// Data present but invalid
	return db.NewRecordStmtAdditional(COMP_SOURCE_CODE_URL, id, result, 0.0, false)
}

func bsiV11ComponentDownloadURL(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	result := strings.TrimSpace(component.GetDownloadLocationURL())

	if result == "" {
		return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, "", 0.0, true)
	}
	if bsiIsValidURL(result) {
		return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, result, 10.0, false)
	}
	return db.NewRecordStmtAdditional(COMP_DOWNLOAD_URL, id, result, 0.0, false)
}

func bsiV11ComponentSourceHash(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)
	result := strings.TrimSpace(component.SourceCodeHash())

	if result == "" {
		return db.NewRecordStmtAdditional(COMP_SOURCE_HASH, id, "", 0.0, true)
	}
	return db.NewRecordStmtAdditional(COMP_SOURCE_HASH, id, result, 10.0, false)
}

func bsiV11ComponentOtherUniqueIdentifiers(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Check PURLs
	for _, p := range component.GetPurls() {
		v := strings.TrimSpace(string(p))
		if v != "" {
			return db.NewRecordStmtAdditional(COMP_OTHER_UNIQ_IDS, id, "purl: "+v, 10.0, false)
		}
	}

	// Check CPEs (fallback)
	for _, cpe := range component.GetCpes() {
		v := strings.TrimSpace(string(cpe))
		if v != "" {
			return db.NewRecordStmtAdditional(COMP_OTHER_UNIQ_IDS, id, "cpe: "+v, 10.0, false)
		}
	}

	// No identifiers => prerequisite not met => N/A
	return db.NewRecordStmtAdditional(COMP_OTHER_UNIQ_IDS, id, "", 0.0, true)
}
