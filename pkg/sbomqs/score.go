package sbomqs

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

type Config struct {
	// Categories to score (e.g., "security", "completeness")
	Categories []string

	// Features to score (e.g., "components", "dependencies")
	Features []string

	// Optional path to a config file for filters
	ConfigFile string

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

func Score(ctx context.Context, path string, config Config) (ScoreResult, error) {
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

	blob, signature, publicKey, err := common.GetSignatureBundle(ctx, path, config.SignatureBundle.SigValue, config.SignatureBundle.PublicKey)
	if err != nil {
		log.Debugf("common.GetSignatureBundle failed for file :%s\n", path)
		fmt.Printf("failed to get signature bundle for %s\n", path)
		// return err
	}

	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
		Blob:      blob,
	}
	config.SignatureBundle = sig

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

	if config.ConfigFile != "" {
		filters, err := scorer.ReadConfigFile(config.ConfigFile)
		if err != nil {
			log.Debugf("failed to read config file %s: %v\n", config.ConfigFile, err)
			result.Errors = append(result.Errors, fmt.Sprintf("failed to read config file %s: %v", config.ConfigFile, err))
			return result, err
		}

		if len(filters) <= 0 {
			log.Debugf("no enabled filters found in config file %s\n", config.ConfigFile)
			result.Errors = append(result.Errors, fmt.Sprintf("no enabled filters found in config file %s", config.ConfigFile))
			return result, fmt.Errorf("no enabled filters found in config file %s", config.ConfigFile)
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

func ScoreSBOM(ctx context.Context, config Config, paths []string) ([]ScoreResult, error) {
	log := logger.FromContext(ctx)
	var results []ScoreResult

	// 1. Validate paths
	validPaths := validatePaths(paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// 2. Validate config
	if err := validateConfig(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	}

	// 3. Process each valid SBOM file
	log.Debugf("processing %d SBOM files", len(validPaths))

	for _, path := range validPaths {
		switch {
		case utils.IsURL(path):
			log.Debugf("processing URL: %s", path)
			sbomFile, sig, err := processURLInput(ctx, path, config)
			if err != nil {
				log.Warnf("failed to process URL: %s: %v", path, err)
				continue
			}
			defer os.Remove(sbomFile.Name())
			defer sbomFile.Close()

			result, err := processSBOMInput(ctx, sbomFile, sig, config, path)
			if err != nil {
				log.Warnf("failed to score SBOM from URL %s: %v", path, err)
				continue
			}
			results = append(results, result)

		case utils.IsDir(path):
			log.Debugf("processing directory: %s", path)
			dirResults := processDirectory(ctx, path, config)
			results = append(results, dirResults...)

		default:
			// Is local file or folder
			_, err := os.Stat(path)
			if err != nil {
				log.Warnf("cannot stat path: %s: %v", path, err)
				continue
			}

			log.Debugf("processing file: %s", path)

			// get the SBOM document
			sbomFile, err := getFileHandle(ctx, path)
			if err != nil {
				log.Warnf("failed to get file: %s: %v", path, err)
			}

			// get the signature bundle
			sig, err := getSignature(ctx, path, config.SignatureBundle.SigValue, config.SignatureBundle.PublicKey)
			if err != nil {
				log.Warnf("failed to get signature for file: %s: %v", path, err)
				continue
			}

			result, err := processSBOMInput(ctx, sbomFile, sig, config, path)
			if err != nil {
				log.Warnf("failed to process SBOM file %s: %v", path, err)
				continue
			}
			results = append(results, result)
		}

		// let's write a seperate funtion to validate paths
		return results, nil
	}
	return results, fmt.Errorf("no valid SBOM files processed")
}

func processSBOMInput(ctx context.Context, sbomFile *os.File, sig sbom.Signature, config Config, path string) (ScoreResult, error) {
	log := logger.FromContext(ctx)
	log.Debug("Processing SBOM input data")

	doc, err := processSBOMDocument(ctx, sbomFile, sig)
	if err != nil {
		return ScoreResult{}, fmt.Errorf("failed to parse SBOM: %w", err)
	}

	sr := scorer.NewScorer(ctx, doc)

	sr, err = applyFilterToScore(ctx, sr, doc, config)
	if err != nil {
		return ScoreResult{}, fmt.Errorf("failed to filter score: %w", err)
	}

	scores := sr.Score()
	return constructResult(ctx, doc, scores, path), nil
}

func constructResult(ctx context.Context, doc sbom.Document, scores scorer.Scores, path string) ScoreResult {
	log := logger.FromContext(ctx)
	log.Debug("Constructing score result")

	result := ScoreResult{
		Spec:          doc.Spec().GetSpecType(),
		SpecVersion:   doc.Spec().GetVersion(),
		FileFormat:    doc.Spec().FileFormat(),
		AvgScore:      scores.AvgScore(),
		NumComponents: len(doc.Components()),
		CreationTime:  doc.Spec().GetCreationTimestamp(),
		document:      doc,
		FileName:      path,
		rawScores:     scores,
	}

	for _, s := range scores.ScoreList() {
		result.Scores = append(result.Scores, ScoreDetail{
			Category:    s.Category(),
			Feature:     s.Feature(),
			Score:       s.Score(),
			MaxScore:    s.MaxScore(),
			Description: s.Descr(),
			Ignored:     s.Ignore(),
		})
	}

	return result
}

func applyFilterToScore(ctx context.Context, sr *scorer.Scorer, doc sbom.Document, config Config) (*scorer.Scorer, error) {
	// sr := scorer.NewScorer(ctx, doc)

	log := logger.FromContext(ctx)
	log.Debug("Applying filters to score")

	config.Features = removeEmptyStrings(config.Features)
	config.Categories = removeEmptyStrings(config.Categories)
	if len(config.Features) > 0 && len(config.Categories) > 0 {
		fmt.Println("Adding mix of features and categories")
		for _, cat := range config.Categories {
			if len(cat) <= 0 {
				continue
			}
			for _, feat := range config.Features {
				if len(feat) <= 0 {
					continue
				}
				filter := scorer.Filter{
					Name:     feat,
					Ftype:    scorer.Mix,
					Category: cat,
				}
				sr.AddFilter(filter)
			}
		}
	} else if len(config.Categories) > 0 {
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
	} else if len(config.Features) > 0 {
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

	if config.ConfigFile != "" {
		filters, err := scorer.ReadConfigFile(config.ConfigFile)
		if err != nil {
			log.Fatalf("failed to read config file %s : %s", config.ConfigFile, err)
		}

		if len(filters) <= 0 {
			log.Fatalf("no enabled filters found in config file %s", config.ConfigFile)
		}

		for _, filter := range filters {
			sr.AddFilter(filter)
		}
	}

	// scores := sr.Score()

	return sr, nil
}
