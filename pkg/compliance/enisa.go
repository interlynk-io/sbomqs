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
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

// ENISA compliance check identifiers.
//
//nolint:revive,stylecheck
const (
	ENISA_SBOM_AUTHOR = iota + 2000
	ENISA_SBOM_TIMESTAMP
	ENISA_SBOM_TOOL_NAME
	ENISA_SBOM_GENERATION_CONTEXT
	ENISA_COMP_NAME
	ENISA_COMP_VERSION
	ENISA_COMP_UNIQ_ID
	ENISA_COMP_PRODUCER
	ENISA_COMP_HASH_VALUE
	ENISA_COMP_HASH_ALGO
	ENISA_COMP_LICENSE
	ENISA_COMP_RELATIONSHIPS
)

func enisaResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.enisaResult()")

	dtb := db.NewDB()

	// SBOM-level checks
	dtb.AddRecord(enisaSBOMAuthor(doc))
	dtb.AddRecord(enisaSBOMTimestamp(doc))
	dtb.AddRecord(enisaSBOMToolName(doc))
	dtb.AddRecord(enisaSBOMGenerationContext(doc))

	// Component-level checks
	dtb.AddRecords(enisaComponents(doc))

	if outFormat == "json" {
		enisaJSONReport(dtb, fileName)
		return
	}
	if outFormat == "basic" {
		enisaBasicReport(dtb, fileName)
		return
	}
	enisaDetailedReport(dtb, fileName, colorOutput)
}

// 1. SBOM Author — Person only
func enisaSBOMAuthor(doc sbom.Document) *db.Record {
	authors := doc.Authors()

	for _, author := range authors {
		if strings.EqualFold(author.GetType(), "person") {
			if val, ok := getAuthorInfo([]sbom.GetAuthor{author}); ok {
				return db.NewRecordStmt(ENISA_SBOM_AUTHOR, "doc", val, SCORE_FULL, "")
			}
		}
	}

	// Check for Organization or Tool to provide helpful message
	for _, author := range authors {
		if strings.EqualFold(author.GetType(), "organization") {
			return db.NewRecordStmt(ENISA_SBOM_AUTHOR, "doc", "", SCORE_ZERO, "Organization found but ENISA requires Person as author")
		}
		if strings.EqualFold(author.GetType(), "tool") {
			return db.NewRecordStmt(ENISA_SBOM_AUTHOR, "doc", "", SCORE_ZERO, "Tool found but ENISA requires Person as author; tool entries are captured separately")
		}
	}

	return db.NewRecordStmt(ENISA_SBOM_AUTHOR, "doc", "", SCORE_ZERO, "")
}

// 2. SBOM Timestamp
func enisaSBOMTimestamp(doc sbom.Document) *db.Record {
	result := doc.Spec().GetCreationTimestamp()
	if result == "" {
		return db.NewRecordStmt(ENISA_SBOM_TIMESTAMP, "doc", "", SCORE_ZERO, "")
	}

	_, err := time.Parse(time.RFC3339, result)
	if err != nil {
		return db.NewRecordStmt(ENISA_SBOM_TIMESTAMP, "doc", result, SCORE_ZERO, "")
	}
	return db.NewRecordStmt(ENISA_SBOM_TIMESTAMP, "doc", result, SCORE_FULL, "")
}

// 3. SBOM Tool Name
func enisaSBOMToolName(doc sbom.Document) *db.Record {
	var results []string

	if tools := doc.Tools(); tools != nil {
		for _, tool := range tools {
			name := strings.TrimSpace(tool.GetName())
			if name != "" {
				results = append(results, name)
			}
		}
	}

	result := strings.Join(lo.Uniq(results), "; ")
	if len(results) > 0 {
		return db.NewRecordStmt(ENISA_SBOM_TOOL_NAME, "doc", result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(ENISA_SBOM_TOOL_NAME, "doc", "", SCORE_ZERO, "")
}

// 4. SBOM Generation Context
func enisaSBOMGenerationContext(doc sbom.Document) *db.Record {
	spec := doc.Spec().GetSpecType()
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == string(sbom.SBOMSpecCDX) || (spec == string(sbom.SBOMSpecSPDX) && strings.HasPrefix(ver, "3.")) {
		lifecycles := doc.Lifecycles()
		if len(lifecycles) > 0 {
			return db.NewRecordStmt(ENISA_SBOM_GENERATION_CONTEXT, "doc", strings.Join(lifecycles, ", "), SCORE_FULL, "")
		}
	}

	if spec == string(sbom.SBOMSpecSPDX) {
		if c := doc.Spec().GetComment(); c != "" {
			return db.NewRecordStmt(ENISA_SBOM_GENERATION_CONTEXT, "doc", c, SCORE_FULL, "")
		}
	}

	return db.NewRecordStmt(ENISA_SBOM_GENERATION_CONTEXT, "doc", "", SCORE_ZERO, "")
}

// Component-level checks
func enisaComponents(doc sbom.Document) []*db.Record {
	records := []*db.Record{}

	if len(doc.Components()) == 0 {
		records = append(records, db.NewRecordStmt(ENISA_COMP_NAME, "doc", "", SCORE_ZERO, ""))
		return records
	}

	for _, comp := range doc.Components() {
		id := common.UniqueElementID(comp)
		records = append(records, enisaCompName(comp, id))
		records = append(records, enisaCompVersion(comp, id))
		records = append(records, enisaCompUniqID(comp, id))
		records = append(records, enisaCompProducer(comp, id))
		records = append(records, enisaCompHashValue(comp, id))
		records = append(records, enisaCompHashAlgo(comp, id))
		records = append(records, enisaCompLicense(comp, id))
		records = append(records, enisaCompRelationships(doc, comp, id))
	}
	return records
}

func enisaCompName(comp sbom.GetComponent, id string) *db.Record {
	if result := strings.TrimSpace(comp.GetName()); result != "" {
		return db.NewRecordStmt(ENISA_COMP_NAME, id, result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(ENISA_COMP_NAME, id, "", SCORE_ZERO, "")
}

func enisaCompVersion(comp sbom.GetComponent, id string) *db.Record {
	if result := strings.TrimSpace(comp.GetVersion()); result != "" {
		return db.NewRecordStmt(ENISA_COMP_VERSION, id, result, SCORE_FULL, "")
	}
	return db.NewRecordStmt(ENISA_COMP_VERSION, id, "", SCORE_ZERO, "")
}

func enisaCompUniqID(comp sbom.GetComponent, id string) *db.Record {
	if purls := comp.GetPurls(); len(purls) > 0 {
		val := strings.TrimSpace(string(purls[0]))
		if val != "" {
			return db.NewRecordStmt(ENISA_COMP_UNIQ_ID, id, val, SCORE_FULL, "")
		}
	}
	if cpes := comp.GetCpes(); len(cpes) > 0 {
		val := strings.TrimSpace(string(cpes[0]))
		if val != "" {
			return db.NewRecordStmt(ENISA_COMP_UNIQ_ID, id, val, SCORE_FULL, "")
		}
	}
	if len(comp.Swids()) > 0 {
		return db.NewRecordStmt(ENISA_COMP_UNIQ_ID, id, comp.Swids()[0].String(), SCORE_FULL, "")
	}
	if swhids := comp.Swhids(); len(swhids) > 0 {
		return db.NewRecordStmt(ENISA_COMP_UNIQ_ID, id, swhids[0].String(), SCORE_FULL, "")
	}
	if omnis := comp.OmniborIDs(); len(omnis) > 0 {
		return db.NewRecordStmt(ENISA_COMP_UNIQ_ID, id, omnis[0].String(), SCORE_FULL, "")
	}
	return db.NewRecordStmt(ENISA_COMP_UNIQ_ID, id, "", SCORE_ZERO, "")
}

// Software Producer — Person only
func enisaCompProducer(comp sbom.GetComponent, id string) *db.Record {
	for _, author := range comp.Authors() {
		if strings.EqualFold(author.GetType(), "person") {
			if val, ok := getEntityIdentifier(author.GetName(), author.GetEmail(), ""); ok {
				return db.NewRecordStmt(ENISA_COMP_PRODUCER, id, val, SCORE_FULL, "")
			}
		}
	}

	for _, author := range comp.Authors() {
		if strings.EqualFold(author.GetType(), "organization") {
			return db.NewRecordStmt(ENISA_COMP_PRODUCER, id, "", SCORE_ZERO, "Organization found but ENISA requires Person as producer")
		}
	}

	return db.NewRecordStmt(ENISA_COMP_PRODUCER, id, "", SCORE_ZERO, "")
}

func enisaCompHashValue(comp sbom.GetComponent, id string) *db.Record {
	for _, chk := range comp.GetChecksums() {
		if val := strings.TrimSpace(chk.GetContent()); val != "" {
			return db.NewRecordStmt(ENISA_COMP_HASH_VALUE, id, val, SCORE_FULL, "")
		}
	}
	return db.NewRecordStmt(ENISA_COMP_HASH_VALUE, id, "", SCORE_ZERO, "")
}

func enisaCompHashAlgo(comp sbom.GetComponent, id string) *db.Record {
	for _, chk := range comp.GetChecksums() {
		if algo := strings.TrimSpace(chk.GetAlgo()); algo != "" {
			return db.NewRecordStmt(ENISA_COMP_HASH_ALGO, id, algo, SCORE_FULL, "")
		}
	}
	return db.NewRecordStmt(ENISA_COMP_HASH_ALGO, id, "", SCORE_ZERO, "")
}

func enisaCompLicense(comp sbom.GetComponent, id string) *db.Record {
	licenses := []string{}
	for _, l := range comp.DeclaredLicenses() {
		if l == nil {
			continue
		}
		if ln := l.ShortID(); ln != "" {
			licenses = append(licenses, ln)
		}
	}
	if len(licenses) > 0 {
		result := strings.Join(licenses, "; ")
		return db.NewRecordStmt(ENISA_COMP_LICENSE, id, result, SCORE_FULL, "")
	}

	return db.NewRecordStmt(ENISA_COMP_LICENSE, id, "", SCORE_ZERO, "")
}

func enisaCompRelationships(doc sbom.Document, comp sbom.GetComponent, id string) *db.Record {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return db.NewRecordStmt(ENISA_COMP_RELATIONSHIPS, id, "", SCORE_ZERO, "")
	}

	// If this component is the primary component, check its direct dependencies
	if primary.GetID() == comp.GetID() {
		directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
		if len(directDeps) > 0 {
			return db.NewRecordStmt(ENISA_COMP_RELATIONSHIPS, id, fmt.Sprintf("primary component declares %d top-level dependencies", len(directDeps)), SCORE_FULL, "")
		}
	}

	// For non-primary components, check if they have any declared relationships
	if comp.HasRelationShips() || comp.CountOfDependencies() > 0 {
		return db.NewRecordStmt(ENISA_COMP_RELATIONSHIPS, id, "component has declared relationships", SCORE_FULL, "")
	}

	return db.NewRecordStmt(ENISA_COMP_RELATIONSHIPS, id, "", SCORE_ZERO, "")
}
