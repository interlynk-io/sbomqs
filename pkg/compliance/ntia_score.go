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

func ntiaKeyIdScore(db *db, key int, id string) *ntiaScoreResult {
	records := db.getRecordsByKeyId(key, id)

	if len(records) == 0 {
		return newNtiaScoreResult(id)
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

	return &ntiaScoreResult{
		id:              id,
		requiredScore:   required_score,
		optionalScore:   optional_score,
		requiredRecords: required_recs,
		optionalRecords: optional_recs,
	}
}

func ntiaAggregateScore(db *db) *ntiaScoreResult {
	var results []ntiaScoreResult
	var finalResult ntiaScoreResult

	ids := db.getAllIds()
	for _, id := range ids {
		results = append(results, *ntiaIdScore(db, id))
	}

	for _, r := range results {
		finalResult.requiredScore += r.requiredScore
		finalResult.optionalScore += r.optionalScore
		finalResult.requiredRecords += r.requiredRecords
		finalResult.optionalRecords += r.optionalRecords
	}

	return &finalResult
}

func ntiaIdScore(db *db, id string) *ntiaScoreResult {
	records := db.getRecordsById(id)

	if len(records) == 0 {
		return newNtiaScoreResult(id)
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

	return &ntiaScoreResult{
		id:              id,
		requiredScore:   required_score,
		optionalScore:   optional_score,
		requiredRecords: required_recs,
		optionalRecords: optional_recs,
	}
}
