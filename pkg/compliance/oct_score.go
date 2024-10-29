package compliance

import "github.com/interlynk-io/sbomqs/pkg/compliance/db"

type octScoreResult struct {
	id              string
	requiredScore   float64
	optionalScore   float64
	requiredRecords int
	optionalRecords int
}

func newOctScoreResult(id string) *octScoreResult {
	return &octScoreResult{id: id}
}

func (r *octScoreResult) totalScore() float64 {
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

func (r *octScoreResult) totalRequiredScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}

	return r.requiredScore / float64(r.requiredRecords)
}

func (r *octScoreResult) totalOptionalScore() float64 {
	if r.optionalRecords == 0 {
		return 0.0
	}

	return r.optionalScore / float64(r.optionalRecords)
}

func octKeyIDScore(dtb *db.DB, key int, id string) *octScoreResult {
	records := dtb.GetRecordsByKeyID(key, id)

	if len(records) == 0 {
		return newOctScoreResult(id)
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

	return &octScoreResult{
		id:              id,
		requiredScore:   requiredScore,
		optionalScore:   optionalScore,
		requiredRecords: requiredRecs,
		optionalRecords: optionalRecs,
	}
}

func octAggregateScore(dtb *db.DB) *octScoreResult {
	var results []octScoreResult
	var finalResult octScoreResult

	ids := dtb.GetAllIDs()
	for _, id := range ids {
		results = append(results, *octIDScore(dtb, id))
	}

	for _, r := range results {
		finalResult.requiredScore += r.requiredScore
		finalResult.optionalScore += r.optionalScore
		finalResult.requiredRecords += r.requiredRecords
		finalResult.optionalRecords += r.optionalRecords
	}

	return &finalResult
}

func octIDScore(dtb *db.DB, id string) *octScoreResult {
	records := dtb.GetRecordsByID(id)

	if len(records) == 0 {
		return newOctScoreResult(id)
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

	return &octScoreResult{
		id:              id,
		requiredScore:   requiredScore,
		optionalScore:   optionalScore,
		requiredRecords: requiredRecs,
		optionalRecords: optionalRecs,
	}
}
