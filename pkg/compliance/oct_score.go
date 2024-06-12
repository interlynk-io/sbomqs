package compliance

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

func octKeyIdScore(db *db, key int, id string) *octScoreResult {
	records := db.getRecordsByKeyId(key, id)

	if len(records) == 0 {
		return newOctScoreResult(id)
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

	return &octScoreResult{
		id:              id,
		requiredScore:   required_score,
		optionalScore:   optional_score,
		requiredRecords: required_recs,
		optionalRecords: optional_recs,
	}
}

func octAggregateScore(db *db) *octScoreResult {
	var results []octScoreResult
	var finalResult octScoreResult

	ids := db.getAllIds()
	for _, id := range ids {
		results = append(results, *octIdScore(db, id))
	}

	for _, r := range results {
		finalResult.requiredScore += r.requiredScore
		finalResult.optionalScore += r.optionalScore
		finalResult.requiredRecords += r.requiredRecords
		finalResult.optionalRecords += r.optionalRecords
	}

	return &finalResult
}

func octIdScore(db *db, id string) *octScoreResult {
	records := db.getRecordsById(id)

	if len(records) == 0 {
		return newOctScoreResult(id)
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

	return &octScoreResult{
		id:              id,
		requiredScore:   required_score,
		optionalScore:   optional_score,
		requiredRecords: required_recs,
		optionalRecords: optional_recs,
	}
}
