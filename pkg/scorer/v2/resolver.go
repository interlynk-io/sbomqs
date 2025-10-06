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

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

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

// Rules:
// - If no filters are provided, return the input as-is.
// - If Categories are provided: keep only those categories (by name).
// - If Features are provided: within the kept categories, keep only those features (by key).
// - If both are provided: intersection semantics (category must match, and only listed features remain).
// - Categories that end up with zero features after filtering are dropped.
// - Order is preserved.
func filterCategories(cfg Config, cats []CategorySpec) []CategorySpec {
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
	allowedCategories := toSet(cfg.Categories)
	allowedFeatures := toSet(cfg.Features)

	wantCats := len(allowedCategories) > 0
	wantFeats := len(allowedFeatures) > 0

	out := make([]CategorySpec, 0, len(cats))

	for _, cat := range cats {
		// Category filter (if any)
		if wantCats {
			if _, ok := allowedCategories[strings.ToLower(cat.Name)]; !ok {
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
			if _, ok := allowedFeatures[strings.ToLower(feat.Key)]; ok {
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

func evaluateFeature(doc sbom.Document, feature FeatureSpec) FeatureResult {
	featureResult := feature.Evaluate(doc)

	return FeatureResult{
		Key:     feature.Key,
		Weight:  feature.Weight,
		Score:   featureResult.Score,
		Desc:    featureResult.Desc,
		Ignored: featureResult.Ignore,
	}
}

// scoreAgainstCategories checks SBOM against all defined categories
func scoreAgainstCategories(ctx context.Context, doc sbom.Document, categories []CategorySpec) []CategoryResult {
	log := logger.FromContext(ctx)
	log.Debugf("scoring against categories: ", categories)

	categoryResults := make([]CategoryResult, 0, len(categories))
	for _, cat := range categories {
		categoryResults = append(categoryResults, evaluateCategory(ctx, doc, cat))
	}
	return categoryResults
}

// Evaluate a category (feature-weighted average, ignoring N/A).
func evaluateCategory(ctx context.Context, doc sbom.Document, category CategorySpec) CategoryResult {
	log := logger.FromContext(ctx)
	log.Debugf("evaluating against category: ", category)

	categoryWiseResult := NewCategoryResultFromSpec(category)

	var featureWeight float64             // feature weights actually used
	var scoreWithFeatureWeightage float64 // feature-weighted score sum

	for _, feature := range category.Features {
		featureResult := evaluateFeature(doc, feature)
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

// selectCategoriesToScore returns the exact list of categories we’ll score.
func selectCategoriesToScore(cfg Config) ([]CategorySpec, error) {
	baseCategories := baseCategories() // Identification, Provenance (with their feature specs)

	// filters (by category name and/or feature key).
	newCategories := filterCategories(cfg, baseCategories)

	if len(newCategories) == 0 {
		return nil, fmt.Errorf("no categories to score after applying filters (check config)")
	}

	// Also prune categories that lost all features due to feature-level filters.
	pruned := make([]CategorySpec, 0, len(newCategories))
	for _, cat := range newCategories {
		if len(cat.Features) > 0 {
			pruned = append(pruned, cat)
		}
	}
	if len(pruned) == 0 {
		return nil, fmt.Errorf("no features to score after applying filters (check config)")
	}
	return pruned, nil
}

func removeEmptyStrings(input []string) []string {
	var output []string
	for _, s := range input {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			output = append(output, trimmed)
		}
	}
	return output
}

func normalizeAndValidateCategories(ctx context.Context, categories []string) ([]string, error) {
	log := logger.FromContext(ctx)
	log.Debugf("normalizing anf validating categories: %s", categories)
	var normalized []string

	for _, cat := range categories {

		// normalize using alias
		if alias, ok := CategoryAliases[cat]; ok {
			cat = alias
		}

		// validate if it's a supported category
		if !SupportedCategories[cat] {
			log.Warnf("unsupported category: %s", cat)
			continue
		}
		normalized = append(normalized, cat)
	}

	return normalized, nil
}

// getFileHandle opens a file in read-only mode and returns the handle.
// The caller is responsible for calling Close() on the returned file.
func getFileHandle(ctx context.Context, filePath string) (*os.File, error) {
	log := logger.FromContext(ctx)

	log.Debugf("Opening file for reading: %q", filePath)

	file, err := os.Open(filePath) // read-only
	if err != nil {
		log.Debugf("Failed to open %q: %v", filePath, err)
		return nil, fmt.Errorf("open file for reading: %q: %w", filePath, err)
	}

	log.Debugf("Successfully opened %q", filePath)
	return file, nil
}

func getSignature(ctx context.Context, config Config, path string) (sbom.Signature, error) {
	log := logger.FromContext(ctx)

	sigValue, publicKey := config.SignatureBundle.SigValue, config.SignatureBundle.PublicKey
	if sigValue == "" || publicKey == "" {
		return sbom.Signature{}, nil
	}

	blob, signature, pubKey, err := common.GetSignatureBundle(ctx, path, sigValue, publicKey)
	if err != nil {
		log.Debugf("failed to get signature bundle for file: %s: %v", path, err)
		return sbom.Signature{}, err
	}

	return sbom.Signature{
		SigValue:  signature,
		PublicKey: pubKey,
		Blob:      blob,
	}, nil
}
