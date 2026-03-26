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

import "github.com/interlynk-io/sbomqs/v2/pkg/compliance/db"

// bsiScoreResult accumulates per-element scores across three tiers:
//
//   - required:   §5.2 fields => always counted (Required=true, Ignore=false)
//   - additional: §5.3 fields => counted only when data exists (!Ignore)
//   - optional:   §5.4 fields => tracked for display but never counted in score
type bsiScoreResult struct {
	id                string
	requiredScore     float64
	additionalScore   float64
	optionalScore     float64
	requiredRecords   int
	additionalRecords int
	optionalRecords   int
}

func newBsiScoreResult(id string) *bsiScoreResult {
	return &bsiScoreResult{id: id}
}

// totalScore mirrors ComputeInterlynkProfScore:
// (requiredScore + additionalScore) / (requiredRecords + additionalRecords)
// Optional fields are excluded from the denominator entirely.
func (r *bsiScoreResult) totalScore() float64 {
	total := r.requiredRecords + r.additionalRecords
	if total == 0 {
		return 0.0
	}
	return (r.requiredScore + r.additionalScore) / float64(total)
}

func (r *bsiScoreResult) totalRequiredScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}
	return r.requiredScore / float64(r.requiredRecords)
}

func (r *bsiScoreResult) totalAdditionalScore() float64 {
	if r.additionalRecords == 0 {
		return 0.0
	}
	return r.additionalScore / float64(r.additionalRecords)
}

// totalOptionalScore is informational only — it is NOT part of totalScore().
func (r *bsiScoreResult) totalOptionalScore() float64 {
	if r.optionalRecords == 0 {
		return 0.0
	}
	return r.optionalScore / float64(r.optionalRecords)
}

func bsiKeyIDScore(dtb *db.DB, key int, id string) *bsiScoreResult {
	records := dtb.GetRecordsByKeyID(key, id)

	if len(records) == 0 {
		return newBsiScoreResult(id)
	}

	res := newBsiScoreResult(id)
	for _, r := range records {
		switch {
		case r.Required && !r.Ignore:
			res.requiredScore += r.Score
			res.requiredRecords++

		case r.Additional && !r.Ignore:
			res.additionalScore += r.Score
			res.additionalRecords++

		case !r.Required && !r.Additional:
			res.optionalScore += r.Score
			res.optionalRecords++
		}
	}
	return res
}

func bsiIDScore(dtb *db.DB, id string) *bsiScoreResult {
	records := dtb.GetRecordsByID(id)

	if len(records) == 0 {
		return newBsiScoreResult(id)
	}

	res := newBsiScoreResult(id)
	for _, r := range records {
		switch {
		case r.Required && !r.Ignore:
			res.requiredScore += r.Score
			res.requiredRecords++

		case r.Additional && !r.Ignore:
			res.additionalScore += r.Score
			res.additionalRecords++

		case !r.Required && !r.Additional:
			res.optionalScore += r.Score
			res.optionalRecords++
		}
	}
	return res
}

func bsiAggregateScore(dtb *db.DB) *bsiScoreResult {
	var final bsiScoreResult

	for _, id := range dtb.GetAllIDs() {
		r := bsiIDScore(dtb, id)
		final.requiredScore += r.requiredScore
		final.additionalScore += r.additionalScore
		final.optionalScore += r.optionalScore
		final.requiredRecords += r.requiredRecords
		final.additionalRecords += r.additionalRecords
		final.optionalRecords += r.optionalRecords
	}

	return &final
}
