package comprehenssive

import (
	"context"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

func Evaluate(ctx context.Context, catKeys []catalog.ComprCatKey, catal *catalog.Catalog, doc sbom.Document) api.ComprehensiveResult {
	// var results []api.ComprehensiveResult
	results := api.NewComprResult()
	results.Categories = make([]api.CategoryResult, 0, len(catKeys))

	allCategories := make([]catalog.ComprCatSpec, 0, len(catKeys))

	for _, key := range catKeys {
		category, ok := catal.ComprCategories[key]
		if ok {
			allCategories = append(allCategories, category)
		}
	}

	for _, category := range allCategories {
		catResult := evaluateEachCategory(ctx, doc, category, catal)
		results.Categories = append(results.Categories, catResult)
	}

	return results
}

func evaluateEachCategory(ctx context.Context, doc sbom.Document, category catalog.ComprCatSpec, catal *catalog.Catalog) api.CategoryResult {
	catResult := api.NewCategoryResultFromSpec(category)
	catResult.Features = make([]api.FeatureResult, 0, len(category.Features))

	log := logger.FromContext(ctx)
	log.Debugf("evaluateCategory: %s (features=%d, weight=%.2f)", category.Name, len(category.Features), category.Weight)

	for _, comprFeatKey := range category.Features {

		// extract corresponding categorySpec to a feature
		comprFeat, ok := catal.ComprFeatures[comprFeatKey]
		if !ok {
			continue
		}

		catResult.Features = append(catResult.Features, evaluateFeature(doc, comprFeat))
	}
	catResult.Score = formulae.ComputeCategoryScore(catResult.Features)
	return catResult
}

func evaluateFeature(doc sbom.Document, comprFeat catalog.ComprFeatSpec) api.FeatureResult {
	comprFeatResult := api.NewComprFeatResult(comprFeat)

	// evaluate feature
	res := comprFeat.Evaluate(doc)

	//
	comprFeatResult.Score = res.Score
	comprFeatResult.Desc = res.Desc
	comprFeatResult.Ignored = res.Ignore
	comprFeatResult.Name = comprFeat.Name

	return comprFeatResult
}
