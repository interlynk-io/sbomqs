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
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

// scoreAgainstCategories checks SBOM against all defined categories
func scoreAgainstCategories(ctx context.Context, doc sbom.Document, categories []catalog.ComprCatSpec) []api.CategoryResult {
	log := logger.FromContext(ctx)
	log.Debugf("scoring against categories: ", categories)

	categoryResults := make([]api.CategoryResult, 0, len(categories))
	for _, cat := range categories {
		categoryResults = append(categoryResults, evaluateCategory(ctx, doc, cat))
	}
	return categoryResults
}

// Evaluate a category (feature-weighted average, ignoring N/A).
func evaluateCategory(ctx context.Context, doc sbom.Document, category catalog.ComprCatSpec) api.CategoryResult {
	log := logger.FromContext(ctx)
	log.Debugf("evaluateCategory: %s (features=%d, weight=%.2f)", category.Name, len(category.Features), category.Weight)

	categoryWiseResult := api.NewCategoryResultFromSpec(category)
	categoryWiseResult.Features = make([]api.FeatureResult, 0, len(category.Features))

	for _, feature := range category.Features {
		featureResult := evaluateFeature(doc, feature)
		categoryWiseResult.Features = append(categoryWiseResult.Features, featureResult)
	}

	categoryWiseResult.Score = formulae.ComputeCategoryScore(categoryWiseResult.Features)
	return categoryWiseResult
}

// selectCategoriesToScore returns the exact list of categories we’ll score.
func selectCategoriesToScore(cfg config.Config, catal *catalog.Catalog) ([]catalog.ComprCatSpec, error) {
	baseCategories := catal.BaseCategories()

	// filters (by category name and/or feature key).
	filtered := filterCategories(cfg, baseCategories)

	mats := materializeCategories(catal, filtered) // []api.CategorySpec
	if len(mats) == 0 {
		return nil, fmt.Errorf("no features to score...")
	}
	return mats, nil

	// if len(filtered) == 0 {
	// 	return nil, fmt.Errorf("no categories to score after applying filters (check config)")
	// }

	// // Also prune categories that lost all features due to feature-level filters.
	// pruned := make([]catalog.CategorySpec, 0, len(filtered))
	// for _, cat := range filtered {
	// 	if len(cat.Features) > 0 {
	// 		pruned = append(pruned, cat)
	// 	}
	// }

	// if len(pruned) == 0 {
	// 	return nil, fmt.Errorf("no features to score after applying filters (check config)")
	// }

	// return pruned, nil
}

// turn catalog category/feature keys into api specs with weights/evaluators
func materializeCategories(cat *catalog.Catalog, defs []catalog.ComprCatSpec) []catalog.ComprCatSpec {
	out := make([]catalog.ComprCatSpec, 0, len(defs))
	for _, d := range defs {
		ac := catalog.ComprCatSpec{
			Name:   d.Name,
			Weight: d.Weight,
		}
		ac.Features = make([]catalog.ComprFeatSpec, 0, len(d.Features))
		for _, fk := range d.Features {
			fs, ok := cat.Features[fk] // fs is catalog.FeatureSpec
			if !ok {
				continue // unknown key; skip
			}
			ac.Features = append(ac.Features, catalog.FeatureSpec{
				Key:      string(fk),
				Weight:   fs.Weight,
				Evaluate: fs.Evaluate, // same signature
			})
		}
		if len(ac.Features) > 0 {
			out = append(out, ac)
		}
	}
	return out
}

func evaluateFeature(doc sbom.Document, feature catalog.FeatureSpec) api.FeatureResult {
	featureResult := feature.Evaluate(doc)

	return api.FeatureResult{
		Key:     string(feature.Key),
		Weight:  feature.Weight,
		Score:   featureResult.Score,
		Desc:    featureResult.Desc,
		Ignored: featureResult.Ignore,
	}
}

// Rules:
// - If no filters are provided, return the input as-is.
// - If Categories are provided: keep only those categories (by name).
// - If Features are provided: within the kept categories, keep only those features (by key).
// - If both are provided: intersection semantics (category must match, and only listed features remain).
// - Categories that end up with zero features after filtering are dropped.
// - Order is preserved.
func filterCategories(cfg config.Config, cats []catalog.CategorySpec) []catalog.CategorySpec {
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

	out := make([]catalog.CategorySpec, 0, len(cats))

	for _, cat := range cats {
		if wantCats {
			if _, ok := allowedCategories[strings.ToLower(string(cat.Key))]; !ok {
				continue
			}
		}

		if !wantFeats {
			out = append(out, cat)
			continue
		}

		// Feature filter inside category
		filtered := make([]catalog.FeatureKey, 0, len(cat.Features))
		for _, feat := range cat.Features {
			if _, ok := allowedFeatures[strings.ToLower(string(feat))]; ok {
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
