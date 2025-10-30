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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/comprehenssive"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/profiles"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/registry"
	"github.com/interlynk-io/sbomqs/pkg/utils"
)

// ScoreSBOM scores a SBOM for profile or comprehenssive scoring.
// It validates input, builds the scoring catalog once, then iterates
// each path (file or URL), parses it into an SBOM document, and evaluates it
// either via profiles or comprehensive scoring. Per-path errors are logged and
// skipped; successful scoring results are collected and returned.
func ScoreSBOM(ctx context.Context, cfg config.Config, paths []string) ([]api.Result, error) {
	log := logger.FromContext(ctx)

	// 1. Validate paths
	validPaths := validateAndExpandPaths(ctx, paths)
	if len(validPaths) == 0 {
		return nil, fmt.Errorf("no valid paths provided")
	}

	// 2) Initialize the catalog (features, categories, profiles) once.
	catalog := registry.InitializeCatalog()

	// 3) validate config
	if err := validateConfig(ctx, catalog, &cfg); err != nil {
		return nil, fmt.Errorf("failed to validate SBOM configuration: %w", err)
	}

	results := make([]api.Result, 0, len(validPaths))
	processed := 0

	for _, p := range validPaths {
		res, err := scoreOnePath(ctx, catalog, cfg, p)
		if err != nil {
			log.Warnf("skip %s: %v", p, err)
			continue
		}
		res.Meta.Filename = p
		results = append(results, res)
		processed++
	}

	if processed == 0 {
		return nil, fmt.Errorf("no valid SBOM files processed")
	}
	return results, nil
}

// scoreOnePath opens a local file or downloads a URL, parses it into a document,
// and then evaluates each SBOM, and returns the single SBOM scoring result
func scoreOnePath(ctx context.Context, catalog *catalog.Catalog, cfg config.Config, path string) (api.Result, error) {
	file, doc, err := openAndParse(ctx, cfg, path)
	if err != nil {
		return api.Result{}, err
	}
	defer file.Close()

	res, err := SBOMEvaluation(ctx, catalog, cfg, doc)
	res.InterlynkScore = formulae.ComputeInterlynkScore(res.Comprehensive.Categories)
	res.Grade = formulae.ToGrade(res.InterlynkScore)
	res.Doc = doc

	return res, err
}

// openAndParse normalizes the path (file or URL), extracts the signature,
// opens/creates a file handle, and constructs an sbom.Document
// and return file handle, sbom document
func openAndParse(ctx context.Context, cfg config.Config, path string) (*os.File, sbom.Document, error) {
	var (
		f   *os.File
		err error
	)

	if utils.IsURL(path) {
		f, err = ProcessURLPath(ctx, cfg, path)
		if err != nil {
			return nil, nil, fmt.Errorf("process URL: %s: %w", path, err)
		}
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open file for reading: %q: %w", path, err)
		}
	}

	sig, err := ExtractSignature(ctx, cfg, f.Name())
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("get signature for %q: %w", path, err)
	}

	doc, err := sbom.NewSBOMDocument(ctx, f, sig)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("parse error for %q: %w", path, err)
	}

	return f, doc, nil
}

// SBOMEvaluation decides between profile-based and comprehensive scoring,
// delegates to a focused helper, and returns a single SBOM scoring result.
func SBOMEvaluation(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
	if profilePresent(cfg) {
		return evaluateProfiles(ctx, catal, cfg, doc)
	}
	return evaluateComprehensive(ctx, catal, cfg, doc)
}

func profilePresent(cfg config.Config) bool {
	return len(cfg.Profile) > 0
}

func evaluateProfiles(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
	result := api.NewResult(doc)

	profileKeys := catal.ResolveProfileKeys(cfg.Profile)
	if len(profileKeys) == 0 {
		return *result, fmt.Errorf("no valid profiles resolved from: %v", cfg.Profile)
	}

	profResults := profiles.Evaluate(ctx, catal, profileKeys, doc)
	result.Profiles = append(result.Profiles, profResults...)

	return *result, nil
}

func evaluateComprehensive(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
	// Comprehensive Scoring

	result := api.NewResult(doc)

	catKeys := selectCategoriesToScore(cfg, catal)
	if len(catKeys) == 0 {
		return api.Result{}, fmt.Errorf("no categories to score (check config filters)")
	}

	comprResult := comprehenssive.Evaluate(ctx, catKeys, catal, doc)
	result.Comprehensive = &comprResult

	// log.Debugf("selected categories for evaluation: %s", strings.Join(string(catKeys)), ", ")

	// // Score SBOM by categories
	// catEvaluationResults := scoreAgainstCategories(ctx, doc, categoriesToScore)
	// interlynkScore := formulae.ComputeInterlynkScore(catEvaluationResults)

	// result.Comprehensive.InterlynkScore = interlynkScore
	// result.Comprehensive.Grade = formulae.ToGrade(interlynkScore)
	// result.Comprehensive.Categories = catEvaluationResults

	return *result, nil
}

// SBOMEvaluation evaluates a SBOM for profiles or comprehensive scoring.
// If profile flag is set, it performs profile scoring
// computes the Interlynk score + grade, and returns the comprehensive result.
// func SBOMEvaluation(ctx context.Context, catal *catalog.Catalog, cfg config.Config, doc sbom.Document) (api.Result, error) {
// 	log := logger.FromContext(ctx)
// 	log.Debugf("evaluating SBOM")

// 	result := api.NewResult(doc)

// 	if len(cfg.Profile) > 0 {

// 		profileKeys := catal.ResolveProfileKeys(cfg.Profile)
// 		if len(profileKeys) == 0 {
// 			return *result, fmt.Errorf("no valid profiles resolved from: %v", cfg.Profile)
// 		}

// 		profResults := profiles.Evaluate(ctx, catal, profileKeys, doc)
// 		result.Profiles = append(result.Profiles, profResults...)

// 		return *result, nil
// 	}

// 	// Comprehensive Scoring
// 	categoriesToScore, err := selectCategoriesToScore(cfg, catal)
// 	if err != nil {
// 		return api.Result{}, err
// 	}

// 	if len(categoriesToScore) == 0 {
// 		return api.Result{}, fmt.Errorf("no categories to score (check config filters)")
// 	}

// 	// Log category names (readable)
// 	log.Debugf("selected categories for evaluation: %s", strings.Join(CategoryNames(categoriesToScore), ", "))

// 	// Score SBOM by categories
// 	catEvaluationResults := scoreAgainstCategories(ctx, doc, categoriesToScore)
// 	interlynkScore := formulae.ComputeInterlynkScore(catEvaluationResults)

// 	result.Comprehensive.InterlynkScore = interlynkScore
// 	result.Comprehensive.Grade = formulae.ToGrade(interlynkScore)
// 	result.Comprehensive.Categories = catEvaluationResults

// 	return *result, nil
// }
