package sbomqs

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
)

type Config struct {
	// Categories to score (e.g., "security", "completeness")
	Categories []string

	// Features to score (e.g., "components", "dependencies")
	Features []string

	// Optional path to a config file for filters
	ConfigPath string

	SignatureBundle sbom.Signature
}

type ScoreResult struct {
	FileName      string
	Spec          string
	SpecVersion   string
	FileFormat    string
	AvgScore      float64
	NumComponents int
	CreationTime  string
	Scores        []ScoreDetail
	Errors        []string

	document  sbom.Document // (for CLI reporting)
	rawScores scorer.Scores // (for CLI reporting)
}

func (r *ScoreResult) Document() sbom.Document {
	return r.document
}

func (r *ScoreResult) RawScores() scorer.Scores {
	return r.rawScores
}

type ScoreDetail struct {
	Category    string  // e.g., "NTIA-minimum-elements"
	Feature     string  // e.g., "comp_with_name"
	Score       float64 // e.g., 10.0
	MaxScore    float64 // e.g., 10.0
	Description string  // e.g., "38/38 have names"
	Ignored     bool    // e.g., false
}

func ScoreSBOM(ctx context.Context, path string, config Config) (ScoreResult, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", path)

	var result ScoreResult
	result.FileName = path

	if _, err := os.Stat(path); err != nil {
		log.Debugf("os.Stat failed for file: %s\n", path)
		result.Errors = append(result.Errors, fmt.Sprintf("failed to stat %s: %v", path, err))
		return result, err
	}

	f, err := os.ReadFile(path)
	if err != nil {
		log.Debugf("os.ReadFile failed for file: %s\n", path)
		result.Errors = append(result.Errors, fmt.Sprintf("failed to read %s: %v", path, err))

	}

	return ScoreSBOMData(ctx, f, config)
}

func ScoreSBOMData(ctx context.Context, data []byte, config Config) (ScoreResult, error) {
	log := logger.FromContext(ctx)
	log.Debug("Processing SBOM data")

	var result ScoreResult
	result.FileName = "in-memory-data"

	reader := bytes.NewReader(data)

	// Parse the SBOM from raw data
	doc, err := sbom.NewSBOMDocument(ctx, reader, config.SignatureBundle)
	if err != nil {
		log.Debugf("failed to create sbom document from data: %v\n", err)
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse SBOM data: %v", err))
		return result, err
	}

	// Populate metadata
	result.document = doc
	result.Spec = doc.Spec().GetSpecType()
	result.SpecVersion = doc.Spec().GetVersion()
	result.FileFormat = doc.Spec().FileFormat()
	result.NumComponents = len(doc.Components())
	result.CreationTime = doc.Spec().GetCreationTimestamp()

	// Create a scorer and apply filters
	sr := scorer.NewScorer(ctx, doc)

	if len(config.Categories) > 0 {
		for _, category := range config.Categories {
			if len(category) <= 0 {
				continue
			}
			filter := scorer.Filter{
				Name:  category,
				Ftype: scorer.Category,
			}
			sr.AddFilter(filter)
		}
	}

	if len(config.Features) > 0 {
		for _, feature := range config.Features {
			if len(feature) <= 0 {
				continue
			}
			filter := scorer.Filter{
				Name:  feature,
				Ftype: scorer.Feature,
			}
			sr.AddFilter(filter)
		}
	}

	if config.ConfigPath != "" {
		filters, err := scorer.ReadConfigFile(config.ConfigPath)
		if err != nil {
			log.Debugf("failed to read config file %s: %v\n", config.ConfigPath, err)
			result.Errors = append(result.Errors, fmt.Sprintf("failed to read config file %s: %v", config.ConfigPath, err))
			return result, err
		}

		if len(filters) <= 0 {
			log.Debugf("no enabled filters found in config file %s\n", config.ConfigPath)
			result.Errors = append(result.Errors, fmt.Sprintf("no enabled filters found in config file %s", config.ConfigPath))
			return result, fmt.Errorf("no enabled filters found in config file %s", config.ConfigPath)
		}

		for _, f := range filters {
			filter := scorer.Filter{
				Name:  f.Name,
				Ftype: f.Ftype,
			}
			sr.AddFilter(filter)
		}
	}

	// Score the SBOM
	scrs := sr.Score()
	result.rawScores = scrs
	result.AvgScore = scrs.AvgScore()

	// Populate detailed scores
	result.Scores = make([]ScoreDetail, 0, len(scrs.ScoreList()))
	for _, s := range scrs.ScoreList() {
		result.Scores = append(result.Scores, ScoreDetail{
			Category:    s.Category(),
			Feature:     s.Feature(),
			Score:       s.Score(),
			MaxScore:    s.MaxScore(),
			Description: s.Descr(),
			Ignored:     s.Ignore(),
		})
	}

	return result, nil
}
