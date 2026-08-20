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

import "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"

// cisa2026ScoreResult accumulates per-element scores.
// CISA 2026 has only Required fields (all 17 minimum elements are required).
// Optional records (N/A) are tracked for display but never counted in score.
type cisa2026ScoreResult struct {
	id              string
	requiredScore   float64
	optionalScore   float64
	requiredRecords int
	optionalRecords int
}

func newCisa2026ScoreResult(id string) *cisa2026ScoreResult {
	return &cisa2026ScoreResult{id: id}
}

// totalScore = requiredScore / requiredRecords
// Optional fields are excluded from the denominator entirely.
func (r *cisa2026ScoreResult) totalScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}
	return r.requiredScore / float64(r.requiredRecords)
}

func (r *cisa2026ScoreResult) totalRequiredScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}
	return r.requiredScore / float64(r.requiredRecords)
}

// totalOptionalScore is informational only — it is NOT part of totalScore().
func (r *cisa2026ScoreResult) totalOptionalScore() float64 {
	if r.optionalRecords == 0 {
		return 0.0
	}
	return r.optionalScore / float64(r.optionalRecords)
}

func cisa2026KeyIDScore(dtb *db.DB, key int, id string) *cisa2026ScoreResult {
	records := dtb.GetRecordsByKeyID(key, id)

	if len(records) == 0 {
		return newCisa2026ScoreResult(id)
	}

	res := newCisa2026ScoreResult(id)
	for _, r := range records {
		if r.Required {
			res.requiredScore += r.Score
			res.requiredRecords++
		} else {
			res.optionalScore += r.Score
			res.optionalRecords++
		}
	}
	return res
}

func cisa2026IDScore(dtb *db.DB, id string) *cisa2026ScoreResult {
	records := dtb.GetRecordsByID(id)

	if len(records) == 0 {
		return newCisa2026ScoreResult(id)
	}

	res := newCisa2026ScoreResult(id)
	for _, r := range records {
		if r.Required {
			res.requiredScore += r.Score
			res.requiredRecords++
		} else {
			res.optionalScore += r.Score
			res.optionalRecords++
		}
	}
	return res
}

func cisa2026AggregateScore(dtb *db.DB) *cisa2026ScoreResult {
	var final cisa2026ScoreResult

	for _, id := range dtb.GetAllIDs() {
		r := cisa2026IDScore(dtb, id)
		final.requiredScore += r.requiredScore
		final.optionalScore += r.optionalScore
		final.requiredRecords += r.requiredRecords
		final.optionalRecords += r.optionalRecords
	}

	return &final
}
