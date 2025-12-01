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

package fsct

import "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"

type fsctScoreResult struct {
	id              string
	requiredScore   float64
	optionalScore   float64
	requiredRecords int
	optionalRecords int
}

func newFsctScoreResult(id string) *fsctScoreResult {
	return &fsctScoreResult{id: id}
}

func (r *fsctScoreResult) totalScore() float64 {
	if r.requiredRecords == 0 && r.optionalRecords == 0 {
		return 0.0
	}

	if r.requiredRecords != 0 && r.optionalRecords != 0 {
		return (r.totalRequiredScore() + r.totalOptionalScore()) / 2
	}

	if r.requiredRecords == 0 && r.optionalRecords != 0 {
		return r.totalOptionalScore()
	}

	return r.totalRequiredScore()
}

func (r *fsctScoreResult) totalRequiredScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}

	return r.requiredScore / float64(r.requiredRecords)
}

func (r *fsctScoreResult) totalOptionalScore() float64 {
	if r.optionalRecords == 0 {
		return 0.0
	}

	return r.optionalScore / float64(r.optionalRecords)
}

func fsctKeyIDScore(db *db.DB, key int, id string) *fsctScoreResult {
	records := db.GetRecordsByKeyID(key, id)

	if len(records) == 0 {
		return newFsctScoreResult(id)
	}

	requiredScore := 0.0
	optionalScore := 0.0

	requiredRecs := 0
	optionalRecs := 0

	for _, r := range records {
		if r.Required {
			requiredScore += r.Score
			requiredRecs++
		} else {
			optionalScore += r.Score
			optionalRecs++
		}
	}

	return &fsctScoreResult{
		id:              id,
		requiredScore:   requiredScore,
		optionalScore:   optionalScore,
		requiredRecords: requiredRecs,
		optionalRecords: optionalRecs,
	}
}

func fsctIDScore(db *db.DB, id string) *fsctScoreResult {
	records := db.GetRecordsByID(id)

	if len(records) == 0 {
		return newFsctScoreResult(id)
	}

	requiredScore := 0.0
	optionalScore := 0.0

	requiredRecs := 0
	optionalRecs := 0

	for _, r := range records {
		if r.Required {
			requiredScore += r.Score
			requiredRecs++
		} else {
			optionalScore += r.Score
			optionalRecs++
		}
	}

	return &fsctScoreResult{
		id:              id,
		requiredScore:   requiredScore,
		optionalScore:   optionalScore,
		requiredRecords: requiredRecs,
		optionalRecords: optionalRecs,
	}
}

func fsctAggregateScore(db *db.DB) *fsctScoreResult {
	var finalResult fsctScoreResult

	ids := db.GetAllIDs()
	results := make([]fsctScoreResult, 0, len(ids))
	for _, id := range ids {
		results = append(results, *fsctIDScore(db, id))
	}

	for _, r := range results {
		finalResult.requiredScore += r.requiredScore
		finalResult.optionalScore += r.optionalScore
		finalResult.requiredRecords += r.requiredRecords
		finalResult.optionalRecords += r.optionalRecords
	}

	return &finalResult
}
