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

var (
	validBsiSpdxVersions = []string{"SPDX-2.3"}
	validSpdxVersion     = []string{"SPDX-2.1", "SPDX-2.2", "SPDX-2.3"}
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
)

func bsiResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.bsiResult()")

	dtb := db.NewDB()

	// Required SBOM-level checks
	dtb.AddRecord(bsiv11SBOMCreator(doc))
	dtb.AddRecord(bsiv11SBOMTimestamp(doc))

	// Additional SBOM-level checks
	dtb.AddRecord(bsiv11SBOMURI(doc))
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

func bsiv11SBOMCreator(doc sbom.Document) *db.Record {

	// Authors: valid email only
	for _, author := range doc.Authors() {
		if bsiIsValidEmail(author.GetEmail()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", author.GetEmail(), 10.0, "")
		}
	}

	// Manufacturer: email -> URL -> contacts email (checked before supplier per BSI spec)
	if m := doc.Manufacturer(); m != nil {
		if bsiIsValidEmail(m.GetEmail()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", m.GetEmail(), 10.0, "")
		}

		if bsiIsValidURL(m.GetURL()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", m.GetURL(), 10.0, "")
		}

		for _, c := range m.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(SBOM_CREATOR, "doc", c.GetEmail(), 10.0, "")
			}
		}
	}

	// Supplier: email -> URL -> contacts email (fallback)
	if s := doc.Supplier(); s != nil {
		if bsiIsValidEmail(s.GetEmail()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", s.GetEmail(), 10.0, "")
		}

		if bsiIsValidURL(s.GetURL()) {
			return db.NewRecordStmt(SBOM_CREATOR, "doc", s.GetURL(), 10.0, "")
		}

		for _, c := range s.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(SBOM_CREATOR, "doc", c.GetEmail(), 10.0, "")
			}
		}
	}

	return db.NewRecordStmt(SBOM_CREATOR, "doc", "", 0.0, "")
}

func bsiv11SBOMTimestamp(doc sbom.Document) *db.Record {
	result, score := "", 0.0
	result = strings.TrimSpace(doc.Spec().GetCreationTimestamp())

	if result != "" {
		if _, err := time.Parse(time.RFC3339, result); err == nil {
			score = 10.0
		}
	}
	return db.NewRecordStmt(SBOM_TIMESTAMP, "doc", result, score, "")
}

func bsiv11SBOMURI(doc sbom.Document) *db.Record {
	uri := strings.TrimSpace(doc.Spec().GetURI())

	if uri == "" {
		return db.NewRecordStmt(SBOM_URI, "doc", "", 0.0, "")
	}

	if !bsiIsValidURL(uri) && !strings.HasPrefix(uri, "urn:") {
		return db.NewRecordStmt(SBOM_URI, "doc", uri, 0.0, "")
	}

	brokenResult := breakLongString(uri, 50)
	result := strings.Join(brokenResult, "\n")
	return db.NewRecordStmt(SBOM_URI, "doc", result, 10.0, "")
}

func bsiComponents(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records := append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "", 0.0, ""))
		return records
	}

	for _, component := range doc.Components() {
		records = append(records, bsiv11ComponentCreator(component))
		records = append(records, bsiv11ComponentName(component))
		records = append(records, bsiv11ComponentVersion(component))
		records = append(records, bsiv11ComponentDependencies(doc, component))
		records = append(records, bsiv11ComponentLicense(component))
		records = append(records, bsiv11ComponentHash(component))

		// Assitional fields
		records = append(records, bsiv11ComponentSourceCodeURL(component))
		records = append(records, bsiv11ComponentDownloadURL(component))
		records = append(records, bsiv11ComponentSourceHash(component))
		records = append(records, bsiv11ComponentOtherUniqueIdentifiers(component))
	}

	records = append(records, db.NewRecordStmt(SBOM_COMPONENTS, "doc", "present", 10.0, ""))

	return records
}

func bsiv11ComponentCreator(component sbom.GetComponent) *db.Record {
	id := common.UniqueElementID(component)

	// Authors: valid email only
	for _, a := range component.Authors() {
		if bsiIsValidEmail(a.GetEmail()) {
			return db.NewRecordStmt(COMP_CREATOR, id, a.GetEmail(), 10.0, "")
		}
	}

	// Manufacturer: email -> URL -> contacts email (checked before supplier per BSI spec)
	if m := component.Manufacturer(); !m.IsAbsent() {
		if bsiIsValidEmail(m.GetEmail()) {
			return db.NewRecordStmt(COMP_CREATOR, id, m.GetEmail(), 10.0, "")
		}
		if bsiIsValidURL(m.GetURL()) {
			return db.NewRecordStmt(COMP_CREATOR, id, m.GetURL(), 10.0, "")
		}
		for _, c := range m.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(COMP_CREATOR, id, c.GetEmail(), 10.0, "")
			}
		}
	}

	// Suppliers: email -> URL -> contacts email (fallback)
	if s := component.Suppliers(); !s.IsAbsent() {
		if bsiIsValidEmail(s.GetEmail()) {
			return db.NewRecordStmt(COMP_CREATOR, id, s.GetEmail(), 10.0, "")
		}
		if bsiIsValidURL(s.GetURL()) {
			return db.NewRecordStmt(COMP_CREATOR, id, s.GetURL(), 10.0, "")
		}
		for _, c := range s.GetContacts() {
			if bsiIsValidEmail(c.GetEmail()) {
				return db.NewRecordStmt(COMP_CREATOR, id, c.GetEmail(), 10.0, "")
			}
		}
	}

	return db.NewRecordStmt(COMP_CREATOR, id, "", 0.0, "")
}

func bsiv11ComponentName(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.GetName())

	if result != "" {
		return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_NAME, common.UniqueElementID(component), "", 0.0, "")
}

func bsiv11ComponentVersion(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.GetVersion())

	if result != "" {
		return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), result, 10.0, "")
	}

	return db.NewRecordStmt(COMP_VERSION, common.UniqueElementID(component), "", 0.0, "")
}

// bsiv11ComponentDependencies reports dependency enumeration for a single component
// according to BSI TR-03183.
//
// BSI semantics:
//   - Dependency evaluation is strictly component-scoped (not SBOM- or primary-scoped).
//   - A component MAY declare zero dependencies (valid leaf component).
//   - If a component declares dependencies (DEPENDS_ON or CONTAINS),
//     those references MUST be valid and resolvable.
//   - Missing dependencies do NOT cause failure.
//   - Only incorrect or broken dependency declarations result in a failing score.
func bsiv11ComponentDependencies(doc sbom.Document, component sbom.GetComponent) *db.Record {
	compID := component.GetID()

	componentMap := make(map[string]sbom.GetComponent)
	for _, c := range doc.Components() {
		componentMap[c.GetID()] = c
	}

	var declared []string
	for _, r := range doc.GetOutgoingRelations(compID) {
		if strings.EqualFold(r.GetType(), "DEPENDS_ON") || strings.EqualFold(r.GetType(), "CONTAINS") {
			declared = append(declared, r.GetTo())
		}
	}

	// case:1 Leaf components
	if len(declared) == 0 {
		return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "no-dependencies", 10.0, "")
	}

	// case:2 validate each dependency
	var names []string
	for _, depID := range declared {
		depComp, exists := componentMap[depID]
		if !exists {
			return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), "broken-dependencies", 0.0, "")

		}

		name := strings.TrimSpace(depComp.GetName())
		if name != "" {
			names = append(names, name)
		}
	}

	// case:3 validate dependency
	result := strings.Join(names, ", ")

	return db.NewRecordStmt(COMP_DEPTH, common.UniqueElementID(component), result, 10.0, "")
}

func bsiv11ComponentLicense(component sbom.GetComponent) *db.Record {

	score := 0.0
	result := ""

	hasAny := false
	hasValid := false

	// Check Concluded Licenses
	for _, l := range component.ConcludedLicenses() {

		hasAny = true

		id := strings.TrimSpace(l.ShortID())
		if id == "" {
			continue
		}

		u := strings.ToUpper(id)
		if u == "NONE" || u == "NOASSERTION" {
			continue
		}

		// Accept valid SPDX
		if l.Spdx() {
			hasValid = true
			break
		}

		// Accept valid LicenseRef-*
		if l.Custom() && strings.HasPrefix(id, "LicenseRef-") {
			hasValid = true
			break
		}
	}

	//  Check Declared Licenses (fallback)
	if !hasValid {
		for _, l := range component.DeclaredLicenses() {

			hasAny = true

			id := strings.TrimSpace(l.ShortID())
			if id == "" {
				continue
			}

			u := strings.ToUpper(id)
			if u == "NONE" || u == "NOASSERTION" {
				continue
			}

			if l.Spdx() {
				hasValid = true
				break
			}

			if l.Custom() && strings.HasPrefix(id, "LicenseRef-") {
				hasValid = true
				break
			}
		}
	}

	switch {
	case hasValid:
		score = 10.0
		result = "compliant"

	case hasAny:
		score = 0.0
		result = "non-compliant"

	default:
		score = 0.0
		result = "missing"
	}

	return db.NewRecordStmt(COMP_LICENSE, common.UniqueElementID(component), result, score, "")
}

func bsiv11ComponentHash(component sbom.GetComponent) *db.Record {
	result := ""
	score := 0.0

	for _, checksum := range component.GetChecksums() {
		algo := strings.ToUpper(strings.ReplaceAll(checksum.GetAlgo(), "-", ""))
		value := strings.TrimSpace(checksum.GetContent())

		if algo == "SHA256" && value != "" {
			result = checksum.GetContent()
			score = 10.0
			break
		}
	}

	return db.NewRecordStmt(COMP_HASH, common.UniqueElementID(component), result, score, "")
}

func bsiv11ComponentSourceCodeURL(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.GetSourceCodeURL())

	if result != "" {
		if bsiIsValidURL(result) {
			return db.NewRecordStmtOptional(COMP_SOURCE_CODE_URL, common.UniqueElementID(component), result, 10.0)
		}
	}

	return db.NewRecordStmtOptional(COMP_SOURCE_CODE_URL, common.UniqueElementID(component), "", 0.0)
}

func bsiv11ComponentDownloadURL(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.GetDownloadLocationURL())

	if result != "" {
		if bsiIsValidURL(result) {
			return db.NewRecordStmtOptional(COMP_DOWNLOAD_URL, common.UniqueElementID(component), result, 10.0)
		}
	}
	return db.NewRecordStmtOptional(COMP_DOWNLOAD_URL, common.UniqueElementID(component), "", 0.0)
}

func bsiv11ComponentSourceHash(component sbom.GetComponent) *db.Record {
	result := strings.TrimSpace(component.SourceCodeHash())
	score := 0.0

	if result != "" {
		result = component.SourceCodeHash()
		score = 10.0
	}

	return db.NewRecordStmtOptional(COMP_SOURCE_HASH, common.UniqueElementID(component), result, score)
}

func bsiv11ComponentOtherUniqueIdentifiers(component sbom.GetComponent) *db.Record {

	var result string
	score := 0.0

	// Check PURLs
	for _, p := range component.GetPurls() {
		v := strings.TrimSpace(string(p))
		if v != "" {
			result = v
			score = 10.0
			break
		}
	}

	// Check CPEs (fallback)resul
	if result == "" {
		for _, cpe := range component.GetCpes() {
			v := strings.TrimSpace(string(cpe))
			if v != "" {
				result = v
				score = 10.0
				break
			}
		}
	}

	return db.NewRecordStmtOptional(COMP_OTHER_UNIQ_IDS, common.UniqueElementID(component), result, score)
}
