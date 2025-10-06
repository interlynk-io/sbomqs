// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	"context"
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

func ScoreSBOM(ctx context.Context, config Config, paths []string) ([]Result, error) {
	log := logger.FromContext(ctx)

	// Validate paths
	validPaths := validateAndExpandPaths(ctx, paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// Validate config
	if err := validateConfig(ctx, &config); err != nil {
		return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	}

	results := make([]Result, 0, len(validPaths))
	var anyProcessed bool

	for _, path := range validPaths {
		if utils.IsURL(path) {
			log.Debugf("processing URL: %s", path)

			sbomFile, err := processURLPath(ctx, config, path)
			if err != nil {
				log.Warnf("failed to process URL: %s: %v", path, err)
				continue
			}
			defer sbomFile.Close()

			signature, err := getSignature(ctx, config, sbomFile.Name())
			if err != nil {
				return nil, fmt.Errorf("get signature for %q: %w", path, err)
			}

			doc, err := sbom.NewSBOMDocument(ctx, sbomFile, signature)
			if err != nil {
				return nil, fmt.Errorf("parse error: %w", err)
			}

			var sbomScoreResult Result

			// Evaluate SBOM
			sbomScoreResult, err = SBOMEvaluation(ctx, doc, config, signature)
			if err != nil {
				log.Warnf("failed to process SBOM %s: %v", path, err)
				return nil, fmt.Errorf("process SBOM %q: %w", path, err)
			}

			sbomScoreResult.Filename = path

			results = append(results, sbomScoreResult)
			anyProcessed = true
		} else {
			log.Debugf("processing file: %s", path)

			signature, err := getSignature(ctx, config, path)
			if err != nil {
				return nil, fmt.Errorf("get signature for %q: %w", path, err)
			}

			file, err := getFileHandle(ctx, path)
			if err != nil {
				log.Warnf("failed to open file %s: %v", path, err)
				continue
			}
			defer file.Close()

			doc, err := sbom.NewSBOMDocument(ctx, file, signature)
			if err != nil {
				return nil, fmt.Errorf("parse error: %w", err)
			}

			var sbomScoreResult Result

			// Evaluate SBOM
			sbomScoreResult, err = SBOMEvaluation(ctx, doc, config, signature)
			if err != nil {
				log.Warnf("failed to process SBOM %s: %v", path, err)
				return nil, fmt.Errorf("process SBOM %q: %w", path, err)
			}
			sbomScoreResult.Filename = path

			results = append(results, sbomScoreResult)
			anyProcessed = true
		}
	}

	if len(results) == 0 || !anyProcessed {
		return nil, fmt.Errorf("no valid SBOM files processed")
	}

	return results, nil
}

func SBOMEvaluation(ctx context.Context, doc sbom.Document, config Config, sig sbom.Signature) (Result, error) {
	log := logger.FromContext(ctx)
	log.Debugf("evaluating SBOM")

	result := NewResult(doc)

	// Select categories to score
	categoriesToScore, err := selectCategoriesToScore(config)
	if err != nil {
		return Result{}, err
	}

	if len(categoriesToScore) == 0 {
		return Result{}, fmt.Errorf("no categories to score (check config filters)")
	}

	// Log category names (readable)
	log.Debugf("selected categories for evaluation: %s", strings.Join(categoryNames(categoriesToScore), ", "))

	// Score SBOM by categories
	catEvaluationResults := scoreAgainstCategories(ctx, doc, categoriesToScore)
	interlynkScore := computeInterlynkScore(catEvaluationResults)

	result.InterlynkScore = interlynkScore
	result.Grade = toGrade(interlynkScore)
	result.Categories = catEvaluationResults

	return *result, nil
}
