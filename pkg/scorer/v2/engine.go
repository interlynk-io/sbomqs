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
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

func ScoreSBOM(ctx context.Context, config Config, paths []string) ([]Result, error) {
	log := logger.FromContext(ctx)

	// var results []Result
	// var anyProcessed bool

	// Validate paths
	validPaths := validatePaths(ctx, paths)
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
		switch {
		case IsURL(path):
			log.Debugf("processing URL: %s", path)

			// sbomFile, sig, err := processURLInput(ctx, p, config)
			// if err != nil {
			// 	log.Warnf("failed to process URL %s: %v", p, err)
			// 	continue
			// }
			// func() {
			// 	defer func() {
			// 		_ = sbomFile.Close()
			// 		_ = os.Remove(sbomFile.Name())
			// 	}()
			// 	res, err := processSBOMInput(ctx, sbomFile, sig, config, p)
			// 	if err != nil {
			// 		log.Warnf("failed to score SBOM from URL %s: %v", p, err)
			// 		return
			// 	}
			// 	results = append(results, res)
			// 	anyProcessed = true
			// }()

		case IsDir(path):
			// dirResults := processDirectory(ctx, p, config)
			// if len(dirResults) > 0 {
			// 	results = append(results, dirResults...)
			// 	anyProcessed = true
			// }

		default:
			log.Debugf("processing file: %s", path)

			file, err := getFileHandle(ctx, path)
			if err != nil {
				log.Warnf("failed to open file %s: %v", path, err)
				continue
			}
			defer file.Close()

			signature, err := getSignature(
				ctx,
				path,
				config.SignatureBundle.SigValue,
				config.SignatureBundle.PublicKey,
			)
			if err != nil {
				return nil, fmt.Errorf("get signature for %q: %w", path, err)
			}

			result, err := SBOMEvaluation(ctx, file, signature, config, path)
			if err != nil {
				log.Warnf("failed to process SBOM %s: %v", path, err)
				return nil, fmt.Errorf("process SBOM %q: %w", path, err)
			}

			results = append(results, result)
			anyProcessed = true
		}
	}

	if !anyProcessed {
		return nil, fmt.Errorf("no valid SBOM files processed")
	}
	return results, nil
}

func processURLInput(ctx context.Context, url string, config Config) (*os.File, sbom.Signature, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing URL: %s", url)

	if IsGit(url) {
		_, rawURL, err := HandleURL(url)
		if err != nil {
			return nil, sbom.Signature{}, fmt.Errorf("handleURL failed: %w", err)
		}
		url = rawURL
	}

	// download SBOM data from the URL
	data, err := DownloadURL(url)
	if err != nil {
		return nil, sbom.Signature{}, fmt.Errorf("failed to download SBOM from URL %s: %w", url, err)
	}

	// create a temporary file to store the SBOM
	tmpFile, err := os.CreateTemp("", "sbomqs-url-*.json")
	if err != nil {
		return nil, sbom.Signature{}, fmt.Errorf("failed to create temp file for SBOM: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, sbom.Signature{}, fmt.Errorf("failed to write to temp SBOM file: %w", err)
	}

	// Rewind file pointer for reading later
	if _, err := tmpFile.Seek(0, 0); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, sbom.Signature{}, fmt.Errorf("failed to reset temp file pointer: %w", err)
	}

	sig := sbom.Signature{
		SigValue:  config.SignatureBundle.SigValue,
		PublicKey: config.SignatureBundle.PublicKey,
	}

	return tmpFile, sig, nil
}

func SBOMEvaluation(ctx context.Context, file *os.File, sig sbom.Signature, config Config, path string) (Result, error) {
	// Parse the SBOM
	doc, err := sbom.NewSBOMDocument(ctx, file, sig)
	if err != nil {
		return Result{}, fmt.Errorf("parse error: %w", err)
	}

	// Extract metadata for the final report
	meta := extractMeta(doc, path)

	// Select categories to score
	categoriesToScore, err := selectCategoriesToScore(config)
	if err != nil {
		return Result{}, err
	}

	// Score doc against (categories + their features)
	categoriesResults := ScoreAgainstCategories(doc, categoriesToScore)

	// Now update score category weights
	var categoryWeight float64
	var sumOfScoreWithCategoryWeightage float64

	for _, catResult := range categoriesResults {
		categoryWeight += catResult.Weight
		sumOfScoreWithCategoryWeightage += catResult.Score * catResult.Weight
	}

	overallScore := 0.0
	if categoryWeight > 0 {
		overallScore = sumOfScoreWithCategoryWeightage / categoryWeight
	}

	return Result{
		Filename:       path,
		NumComponents:  meta.NumComponents,
		CreationTime:   meta.CreationTime,
		InterlynkScore: overallScore,
		Grade:          toGrade(overallScore),
		Spec:           meta.Spec,
		SpecVersion:    meta.SpecVersion,
		FileFormat:     meta.FileFormat,
		Categories:     categoriesResults,
	}, nil
}

// Best-effort meta extraction (unchanged)
func extractMeta(doc sbom.Document, fileName string) interlynkMeta {
	return interlynkMeta{
		Filename:      fileName,
		NumComponents: len(doc.Components()),
		CreationTime:  doc.Spec().GetCreationTimestamp(),
		Spec:          doc.Spec().GetName(),
		SpecVersion:   doc.Spec().GetVersion(),
		FileFormat:    doc.Spec().FileFormat(),
	}
}

// selectCategoriesToScore returns the exact list of categories we’ll score.
func selectCategoriesToScore(cfg Config) ([]CategorySpec, error) {
	cats := baseCategories() // Identification, Provenance (with their feature specs)

	// filters (by category name and/or feature key).
	cats = filterCategories(cats, cfg)

	if len(cats) == 0 {
		return nil, fmt.Errorf("no categories to score after applying filters (check config)")
	}

	// Also prune categories that lost all features due to feature-level filters.
	pruned := make([]CategorySpec, 0, len(cats))
	for _, c := range cats {
		if len(c.Features) > 0 {
			pruned = append(pruned, c)
		}
	}
	if len(pruned) == 0 {
		return nil, fmt.Errorf("no features to score after applying filters (check config)")
	}
	return pruned, nil
}

func baseCategories() []CategorySpec {
	return []CategorySpec{
		Identification,
		Provenance,
		Integrity,
		Completeness,
		// LicensingAndCompliance
		// VulnerabilityAndTraceability
		// Structural
		// Component Quality
	}
}

// Grade mapping per spec (A: 9–10, B: 8–8.9, C: 7–7.9, D: 5–6.9, F: <5)
func toGrade(v float64) string {
	switch {
	case v >= 9.0:
		return "A"
	case v >= 8.0:
		return "B"
	case v >= 7.0:
		return "C"
	case v >= 5.0:
		return "D"
	default:
		return "F"
	}
}

// Rules (simple and explicit):
// - If no filters are provided, return the input as-is.
// - If Categories are provided: keep only those categories (by name).
// - If Features are provided: within the kept categories, keep only those features (by key).
// - If both are provided: intersection semantics (category must match, and only listed features remain).
// - Categories that end up with zero features after filtering are dropped.
// - Order is preserved.
func filterCategories(cats []CategorySpec, cfg Config) []CategorySpec {
	if len(cfg.Categories) == 0 && len(cfg.Features) == 0 {
		return cats
	}

	// Normalize filters once (trim + lowercase) and put them in sets for O(1) lookups.
	toSet := func(ss []string) map[string]struct{} {
		if len(ss) == 0 {
			return nil
		}
		m := make(map[string]struct{}, len(ss))
		for _, s := range ss {
			k := strings.ToLower(strings.TrimSpace(s))
			if k != "" {
				m[k] = struct{}{}
			}
		}
		return m
	}
	catAllow := toSet(cfg.Categories)
	featAllow := toSet(cfg.Features)

	wantCats := len(catAllow) > 0
	wantFeats := len(featAllow) > 0

	out := make([]CategorySpec, 0, len(cats))

	for _, cat := range cats {
		// Category filter (if any)
		if wantCats {
			if _, ok := catAllow[strings.ToLower(cat.Name)]; !ok {
				continue
			}
		}

		// If no feature filter, keep category as-is.
		if !wantFeats {
			out = append(out, cat)
			continue
		}

		// Otherwise, keep only requested features inside this category.
		filtered := make([]FeatureSpec, 0, len(cat.Features))
		for _, feat := range cat.Features {
			if _, ok := featAllow[strings.ToLower(feat.Key)]; ok {
				filtered = append(filtered, feat)
			}
		}
		// Drop category if nothing remains after feature filtering.
		if len(filtered) == 0 {
			continue
		}

		// Append a copy of the category with its filtered feature list.
		cat.Features = filtered
		out = append(out, cat)
	}

	return out
}

func EvaluateFeature(doc sbom.Document, feature FeatureSpec) FeatureResult {
	featureResult := feature.Evaluate(doc)

	return FeatureResult{
		Key:     feature.Key,
		Weight:  feature.Weight,
		Score:   featureResult.Score,
		Desc:    featureResult.Desc,
		Ignored: featureResult.Ignore,
	}
}

// ScoreAgainstCategories checks SBOM against all defined categories
func ScoreAgainstCategories(doc sbom.Document, categories []CategorySpec) []CategoryResult {
	categoryResults := make([]CategoryResult, 0, len(categories))
	for _, cs := range categories {
		categoryResults = append(categoryResults, EvaluateCategory(doc, cs))
	}
	return categoryResults
}

// Evaluate a category (feature-weighted average, ignoring N/A).
func EvaluateCategory(doc sbom.Document, category CategorySpec) CategoryResult {
	categoryWiseResult := CategoryResult{
		Name:   category.Name,
		Weight: category.Weight,
	}

	var featureWeight float64             // feature weights actually used
	var scoreWithFeatureWeightage float64 // feature-weighted score sum

	for _, feature := range category.Features {
		featureResult := EvaluateFeature(doc, feature)
		categoryWiseResult.Features = append(categoryWiseResult.Features, featureResult)

		if featureResult.Ignored {
			continue
		}

		featureWeight += featureResult.Weight
		scoreWithFeatureWeightage += featureResult.Score * featureResult.Weight
	}

	if featureWeight > 0 {
		categoryWiseResult.Score = scoreWithFeatureWeightage / featureWeight
	} else {
		categoryWiseResult.Score = 0
	}
	return categoryWiseResult
}
