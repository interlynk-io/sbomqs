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

package comprehenssive

import (
	"context"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

func Evaluate(ctx context.Context, catal *catalog.Catalog, doc sbom.Document) api.ComprehensiveResult {
	results := api.NewComprResult()
	results.CatResult = make([]api.CategoryResult, 0, len(catal.ComprCategories))

	for _, category := range catal.ComprCategories {
		catResult := evaluateEachCategory(ctx, doc, category, catal)
		results.CatResult = append(results.CatResult, catResult)
	}

	return results
}

func evaluateEachCategory(ctx context.Context, doc sbom.Document, category catalog.ComprCatSpec, catal *catalog.Catalog) api.CategoryResult {
	catResult := api.NewCategoryResultFromSpec(category)
	catResult.Features = make([]api.FeatureResult, 0, len(category.Features))

	log := logger.FromContext(ctx)
	log.Debugf("evaluateCategory: %s (features=%d, weight=%.2f )", category.Name, len(category.Features), category.Weight)

	for _, featSpec := range category.Features {
		catResult.Features = append(catResult.Features, evaluateFeature(doc, featSpec))
	}

	catResult.Score = formulae.ComputeCategoryScore(catResult.Features)
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
