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

package db

// Record holds the result of one compliance check for a single element.
//
// Three-tier scoring model (mirrors the profile ProfFeatScore semantics):
//
//	Required   = true  → §5.2 field; always counted in the score denominator
//	Additional = true  → §5.3 field; counted only when Ignore=false (data exists)
//	Neither          → §5.4 optional field; never counted in the score
//
// Ignore=true means "no basis for evaluation" (tool/format limitation, or
// prerequisite data absent for Additional fields).  It is NOT a softness signal.
type Record struct {
	CheckKey   int
	CheckValue string
	ID         string
	Score      float64
	Required   bool // tier 1: §5.2 — always counted
	Additional bool // tier 2: §5.3 — counted only when !Ignore
	Ignore     bool // true = N/A; no context to evaluate
	Maturity   string
}

func NewRecord() *Record {
	return &Record{}
}

// NewRecordStmt creates a Required (§5.2) record.
// It is always counted in the score; Ignore is always false.
func NewRecordStmt(key int, id, value string, score float64, maturity string) *Record {
	r := NewRecord()
	r.CheckKey = key
	r.CheckValue = value
	r.ID = id
	r.Score = score
	r.Required = true
	r.Maturity = maturity
	return r
}

// NewRecordStmtAdditional creates an Additional (§5.3) record.
// When ignore=true the record is N/A and excluded from scoring.
// When ignore=false the record is counted (pass or fail).
func NewRecordStmtAdditional(key int, id, value string, score float64, ignore bool) *Record {
	r := NewRecord()
	r.CheckKey = key
	r.CheckValue = value
	r.ID = id
	r.Score = score
	r.Additional = true
	r.Ignore = ignore
	return r
}

// NewRecordStmtOptional creates an Optional (§5.4) record.
// Optional records are never counted in the score.
func NewRecordStmtOptional(key int, id, value string, score float64) *Record {
	r := NewRecord()
	r.CheckKey = key
	r.CheckValue = value
	r.ID = id
	r.Score = score
	r.Required = false
	r.Additional = false
	return r
}
