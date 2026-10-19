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

// enisaScoreResult accumulates per-element scores.
// ENISA has only Required fields (all minimum elements are required).
type enisaScoreResult struct {
	id              string
	requiredScore   float64
	optionalScore   float64
	requiredRecords int
	optionalRecords int
}

func newEnisaScoreResult(id string) *enisaScoreResult {
	return &enisaScoreResult{id: id}
}

// totalScore = requiredScore / requiredRecords
func (r *enisaScoreResult) totalScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}
	return r.requiredScore / float64(r.requiredRecords)
}

func (r *enisaScoreResult) totalRequiredScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}
	return r.requiredScore / float64(r.requiredRecords)
}

// totalOptionalScore is informational only — it is NOT part of totalScore().
func (r *enisaScoreResult) totalOptionalScore() float64 {
	if r.optionalRecords == 0 {
		return 0.0
	}
	return r.optionalScore / float64(r.optionalRecords)
}

func enisaKeyIDScore(dtb *db.DB, key int, id string) *enisaScoreResult {
	records := dtb.GetRecordsByKeyID(key, id)

	if len(records) == 0 {
		return newEnisaScoreResult(id)
	}

	res := newEnisaScoreResult(id)
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

func enisaIDScore(dtb *db.DB, id string) *enisaScoreResult {
	records := dtb.GetRecordsByID(id)

	if len(records) == 0 {
		return newEnisaScoreResult(id)
	}

	res := newEnisaScoreResult(id)
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

func enisaAggregateScore(dtb *db.DB) *enisaScoreResult {
	var final enisaScoreResult

	for _, id := range dtb.GetAllIDs() {
		r := enisaIDScore(dtb, id)
		final.requiredScore += r.requiredScore
		final.optionalScore += r.optionalScore
		final.requiredRecords += r.requiredRecords
		final.optionalRecords += r.optionalRecords
	}

	return &final
}
