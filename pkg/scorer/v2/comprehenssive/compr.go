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

// Package comprehenssive runs the comprehenssive categories to produces the final Interlynk score
// and grade. Higher-level code can call Evaluate once and get a complete
// comprehensive scoring result.
package comprehenssive

import (
	"context"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"go.uber.org/zap"
)

func Evaluate(ctx context.Context, catal *catalog.Catalog, doc sbom.Document) api.ComprehensiveResult {
	log := logger.FromContext(ctx)

	log.Info("Starting comprehensive SBOM evaluation",
		zap.Int("categories", len(catal.ComprCategories)),
	)

	results := api.NewComprResult()
	results.CatResult = make([]api.CategoryResult, 0, len(catal.ComprCategories))

	for _, category := range catal.ComprCategories {
		catResult := evaluateEachCategory(ctx, doc, category)
		results.CatResult = append(results.CatResult, catResult)
	}

	results.InterlynkScore = formulae.ComputeInterlynkComprScore(results.CatResult)
	results.Grade = formulae.ToGrade(results.InterlynkScore)

	log.Info("Comprehensive SBOM evaluation completed",
		zap.Float64("score", results.InterlynkScore),
		zap.String("grade", results.Grade),
	)
	return results
}

func evaluateEachCategory(ctx context.Context, doc sbom.Document, category catalog.ComprCatSpec) api.CategoryResult {
	log := logger.FromContext(ctx)

	log.Debug("Evaluating category",
		zap.String("category", category.Name),
		zap.Int("features", len(category.Features)),
		zap.Float64("weight", category.Weight),
	)

	catResult := api.NewCategoryResultFromSpec(category)
	catResult.Features = make([]api.FeatureResult, 0, len(category.Features))

	for _, featSpec := range category.Features {
		catResult.Features = append(catResult.Features, evaluateFeature(doc, featSpec))
	}

	catResult.Score = formulae.ComputeCategoryScore(catResult.Features)

	log.Debug("Category evaluation completed",
		zap.String("category", category.Name),
		zap.Float64("weight", category.Weight),
		zap.Int("features", len(category.Features)),
		zap.Float64("score", catResult.Score),
	)
	return catResult
}

func evaluateFeature(doc sbom.Document, comprFeat catalog.ComprFeatSpec) api.FeatureResult {

	comprFeatResult := api.NewComprFeatResult(comprFeat)

	// evaluate feature
	res := comprFeat.Evaluate(doc)

	comprFeatResult.Score = res.Score
	comprFeatResult.Desc = res.Desc
	comprFeatResult.Ignored = res.Ignore
	comprFeatResult.Name = comprFeat.Name

	return comprFeatResult
}
