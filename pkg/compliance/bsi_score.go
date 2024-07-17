// Copyright 2024 Interlynk.io
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

type bsiScoreResult struct {
	id              string
	requiredScore   float64
	optionalScore   float64
	requiredRecords int
	optionalRecords int
}

func newBsiScoreResult(id string) *bsiScoreResult {
	return &bsiScoreResult{id: id}
}

func (r *bsiScoreResult) totalScore() float64 {
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

func (r *bsiScoreResult) totalRequiredScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}

	return r.requiredScore / float64(r.requiredRecords)
}

func (r *bsiScoreResult) totalOptionalScore() float64 {
	if r.optionalRecords == 0 {
		return 0.0
	}

	return r.optionalScore / float64(r.optionalRecords)
}

func bsiKeyIdScore(db *db, key int, id string) *bsiScoreResult {
	records := db.getRecordsByKeyId(key, id)

	if len(records) == 0 {
		return newBsiScoreResult(id)
	}

	required_score := 0.0
	optional_score := 0.0

	required_recs := 0
	optional_recs := 0

	for _, r := range records {
		if r.required {
			required_score += r.score
			required_recs += 1
		} else {
			optional_score += r.score
			optional_recs += 1
		}
	}

	return &bsiScoreResult{
		id:              id,
		requiredScore:   required_score,
		optionalScore:   optional_score,
		requiredRecords: required_recs,
		optionalRecords: optional_recs,
	}
}

func bsiIdScore(db *db, id string) *bsiScoreResult {
	records := db.getRecordsById(id)

	if len(records) == 0 {
		return newBsiScoreResult(id)
	}

	required_score := 0.0
	optional_score := 0.0

	required_recs := 0
	optional_recs := 0

	for _, r := range records {
		if r.required {
			required_score += r.score
			required_recs += 1
		} else {
			optional_score += r.score
			optional_recs += 1
		}
	}

	return &bsiScoreResult{
		id:              id,
		requiredScore:   required_score,
		optionalScore:   optional_score,
		requiredRecords: required_recs,
		optionalRecords: optional_recs,
	}
}

func bsiAggregateScore(db *db) *bsiScoreResult {
	var results []bsiScoreResult
	var finalResult bsiScoreResult

	ids := db.getAllIds()
	for _, id := range ids {
		results = append(results, *bsiIdScore(db, id))
	}

	for _, r := range results {
		finalResult.requiredScore += r.requiredScore
		finalResult.optionalScore += r.optionalScore
		finalResult.requiredRecords += r.requiredRecords
		finalResult.optionalRecords += r.optionalRecords
	}

	return &finalResult
}
