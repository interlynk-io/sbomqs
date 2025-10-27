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

package score

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/profiles"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/registry"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

func ScoreSBOM(ctx context.Context, cfg config.Config, paths []string) ([]api.Result, error) {
	log := logger.FromContext(ctx)

	// Validate paths
	validPaths := ValidateAndExpandPaths(ctx, paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// Validate config
	if err := ValidateConfig(ctx, &cfg); err != nil {
		return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	}

	// Initialize the catalog (features, categories, profiles) in one go.
	catalog := registry.InitializeCatalog()

	results := make([]api.Result, 0, len(validPaths))
	var anyProcessed bool

	for _, path := range validPaths {
		if utils.IsURL(path) {
			log.Debugf("processing URL: %s", path)

			sbomFile, err := ProcessURLPath(ctx, cfg, path)
			if err != nil {
				log.Warnf("failed to process URL: %s: %v", path, err)
				continue
			}
			defer sbomFile.Close()

			signature, err := ExtractSignature(ctx, cfg, sbomFile.Name())
			if err != nil {
				return nil, fmt.Errorf("get signature for %q: %w", path, err)
			}

			doc, err := sbom.NewSBOMDocument(ctx, sbomFile, signature)
			if err != nil {
				return nil, fmt.Errorf("parse error: %w", err)
			}

			var sbomScoreResult api.Result

			// Evaluate SBOM
			sbomScoreResult, err = SBOMEvaluation(ctx, catalog, cfg, doc)
			if err != nil {
				log.Warnf("failed to process SBOM %s: %v", path, err)
				return nil, fmt.Errorf("process SBOM %q: %w", path, err)
			}

			sbomScoreResult.Meta.Filename = path

			results = append(results, sbomScoreResult)
			anyProcessed = true
		} else {
			log.Debugf("processing file: %s", path)

			signature, err := ExtractSignature(ctx, cfg, path)
			if err != nil {
				return nil, fmt.Errorf("get signature for %q: %w", path, err)
			}

			file, err := os.Open(path)
			if err != nil {
				log.Debugf("Failed to open %q: %v", path, err)
				return nil, fmt.Errorf("open file for reading: %q: %w", path, err)
			}

			defer file.Close()

			doc, err := sbom.NewSBOMDocument(ctx, file, signature)
			if err != nil {
				return nil, fmt.Errorf("parse error: %w", err)
			}

			var sbomScoreResult api.Result

			// Evaluate SBOM
			sbomScoreResult, err = SBOMEvaluation(ctx, catalog, cfg, doc)
			if err != nil {
				log.Warnf("failed to process SBOM %s: %v", path, err)
				return nil, fmt.Errorf("process SBOM %q: %w", path, err)
			}

			sbomScoreResult.Meta.Filename = path

			results = append(results, sbomScoreResult)
			anyProcessed = true
		}
	}

	if len(results) == 0 || !anyProcessed {
		return nil, fmt.Errorf("no valid SBOM files processed")
	}

	return results, nil
}

func SBOMEvaluation(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
	log := logger.FromContext(ctx)
	log.Debugf("evaluating SBOM")

	result := api.NewResult(doc)

	if len(cfg.Profile) > 0 {
		profileKeys := catal.ResolveProfileKeys(cfg.Profile)
		if len(profileKeys) == 0 {
			return *result, fmt.Errorf("no valid profiles resolved from: %v", cfg.Profile)
		}

		profResults, err := profiles.Evaluate(ctx, catal, profileKeys, doc)
		if err != nil {
			return *result, err
		}
		result.Profiles = append(result.Profiles, profResults...)

		return *result, nil
	}

	// Comprehensive Scoring
	categoriesToScore, err := selectCategoriesToScore(cfg, catal)
	if err != nil {
		return api.Result{}, err
	}

	if len(categoriesToScore) == 0 {
		return api.Result{}, fmt.Errorf("no categories to score (check config filters)")
	}

	// Log category names (readable)
	log.Debugf("selected categories for evaluation: %s", strings.Join(CategoryNames(categoriesToScore), ", "))

	// Score SBOM by categories
	catEvaluationResults := scoreAgainstCategories(ctx, doc, categoriesToScore)
	interlynkScore := formulae.ComputeInterlynkScore(catEvaluationResults)

	result.Comprehensive.InterlynkScore = interlynkScore
	result.Comprehensive.Grade = formulae.ToGrade(interlynkScore)
	result.Comprehensive.Categories = catEvaluationResults

	return *result, nil
}
