package compliance

type ntiaScoreResult struct {
	id              string
	requiredScore   float64
	optionalScore   float64
	requiredRecords int
	optionalRecords int
}

func newNtiaScoreResult(id string) *ntiaScoreResult {
	return &ntiaScoreResult{id: id}
}

func (r *ntiaScoreResult) totalScore() float64 {
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

func (r *ntiaScoreResult) totalRequiredScore() float64 {
	if r.requiredRecords == 0 {
		return 0.0
	}

	return r.requiredScore / float64(r.requiredRecords)
}

func (r *ntiaScoreResult) totalOptionalScore() float64 {
	if r.optionalRecords == 0 {
		return 0.0
	}

	return r.optionalScore / float64(r.optionalRecords)
}

func ntiaKeyIDScore(db *db, key int, id string) *ntiaScoreResult {
	records := db.getRecordsByKeyID(key, id)

	if len(records) == 0 {
		return newNtiaScoreResult(id)
	}

	requiredScore := 0.0
	optionalScore := 0.0

	requiredRecs := 0
	optionalRecs := 0

	for _, r := range records {
		if r.required {
			requiredScore += r.score
			requiredRecs++
		} else {
			optionalScore += r.score
			optionalRecs++
		}
	}

	return &ntiaScoreResult{
		id:              id,
		requiredScore:   requiredScore,
		optionalScore:   optionalScore,
		requiredRecords: requiredRecs,
		optionalRecords: optionalRecs,
	}
}

func ntiaAggregateScore(db *db) *ntiaScoreResult {
	var results []ntiaScoreResult
	var finalResult ntiaScoreResult

	ids := db.getAllIDs()
	for _, id := range ids {
		results = append(results, *ntiaIDScore(db, id))
	}

	for _, r := range results {
		finalResult.requiredScore += r.requiredScore
		finalResult.optionalScore += r.optionalScore
		finalResult.requiredRecords += r.requiredRecords
		finalResult.optionalRecords += r.optionalRecords
	}

	return &finalResult
}

func ntiaIDScore(db *db, id string) *ntiaScoreResult {
	records := db.getRecordsByID(id)

	if len(records) == 0 {
		return newNtiaScoreResult(id)
	}

	requiredScore := 0.0
	optionalScore := 0.0

	requiredRecs := 0
	optionalRecs := 0

	for _, r := range records {
		if r.required {
			requiredScore += r.score
			requiredRecs++
		} else {
			optionalScore += r.score
			optionalRecs++
		}
	}

	return &ntiaScoreResult{
		id:              id,
		requiredScore:   requiredScore,
		optionalScore:   optionalScore,
		requiredRecords: requiredRecs,
		optionalRecords: optionalRecs,
	}
}
