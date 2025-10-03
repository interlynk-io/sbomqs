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

var CategoryAliases = map[string]string{
	"identification": "Identification",
	"provenance":     "Provenance",
	"integrity":      "Integrity",
	"completeness":   "Completeness",
	"licensing":      "Licensing",
	"vulnerability":  "Vulnerability",
	"structural":     "Structural",
}

var SupportedCategories = map[string]bool{
	"Identification": true,
	"Provenance":     true,
	"Integrity":      true,
	"Completeness":   true,
	"Licensing":      true,
	"Vulnerability":  true,
	"Structural":     true,
}

var SupportedFeatures = map[string]bool{
	"comp_with_name":             true,
	"comp_with_version":          true,
	"comp_with_identifiers":      true,
	"sbom_creation_timestamp":    true,
	"sbom_authors":               true,
	"sbom_tool_version":          true,
	"sbom_supplier":              true,
	"sbom_namespace":             true,
	"sbom_lifecycle":             true,
	"comp_with_checksums":        true,
	"comp_with_sha256":           true,
	"sbom_signature":             true,
	"comp_with_dependencies":     true,
	"sbom_completeness_declared": true,
	"primary_component":          true,
	"comp_with_source_code":      true,
	"comp_with_supplier":         true,
	"comp_with_purpose":          true,
	"comp_with_licenses":         true,

	"comp_with_valid_licenses":     true,
	"comp_with_declared_licenses":  true,
	"sbom_data_license":            true,
	"comp_no_deprecated_licenses":  true,
	"comp_no_restrictive_licenses": true,
	"comp_with_purl":               true,
	"comp_with_cpe":                true,
	"sbom_spec_declared":           true,
	"sbom_spec_version":            true,
	"sbom_file_format":             true,
	"sbom_schema_valid":            true,
}

func validateFeatures(ctx context.Context, features []string) ([]string, error) {
	log := logger.FromContext(ctx)
	var validFeatures []string

	for _, feature := range features {
		if _, ok := SupportedFeatures[feature]; !ok {
			log.Warnf("unsupported feature: %s", feature)
			continue
		}
		validFeatures = append(validFeatures, feature)
	}
	return validFeatures, nil
}

// validatePaths returns the valid paths.
func validatePaths(ctx context.Context, paths []string) []string {
	log := logger.FromContext(ctx)
	log.Debug("validating paths")

	var validPaths []string

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			log.Debugf("skipping invalid path: %s, error: %v", path, err)
			continue
		}
		validPaths = append(validPaths, path)
	}
	return validPaths
}

func validateConfig(ctx context.Context, config *Config) error {
	log := logger.FromContext(ctx)
	log.Debug("validating configuration")

	if config.ConfigFile != "" {
		if _, err := os.Stat(config.ConfigFile); err != nil {
			return fmt.Errorf("invalid config path: %s: %w", config.ConfigFile, err)
		}
	}
	config.Categories = RemoveEmptyStrings(config.Categories)

	if len(config.Categories) > 0 {
		log.Debugf("validating categories: %v", config.Categories)
		normCategories, err := normalizeAndValidateCategories(ctx, config.Categories)
		if err != nil {
			return fmt.Errorf("failed to normalize and validate categories: %w", err)
		}
		config.Categories = normCategories
	}

	config.Features = RemoveEmptyStrings(config.Features)
	if len(config.Features) > 0 {
		log.Debugf("validating features: %v", config.Features)
		validFeatures, err := validateFeatures(ctx, config.Features)
		if err != nil {
			return fmt.Errorf("failed to validate features: %w", err)
		}
		config.Features = validFeatures
	}

	return nil
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

func getSignature(ctx context.Context, path string, sigValue, publicKey string) (sbom.Signature, error) {
	log := logger.FromContext(ctx)

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
// It applies any filters from config and guards against “empty after filtering”.
func selectCategoriesToScore(cfg Config) ([]CategorySpec, error) {
	cats := baseCategories() // Identification, Provenance (with their feature specs)

	// Apply optional filters (by category name and/or feature key).
	cats = filterCategories(cats, cfg)

	// It’s easy to accidentally filter everything out.
	// Be explicit: if nothing remains, tell the caller instead of silently scoring 0.
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

// filterCategories selects what we will score, based on the user's config.
//
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

// we have to check all the categories against sbom doc
// collect the result for a sbom
// the result will contains CategoryResult
// it will contain name of a category, it's corresponding result
// like feature result
// similarly all categoriesResult will returned.
// the scoredocument function will iterate through each and every categories
// and each categories will iterate though each and every features
// and each feature will call it's corresponding featureFun to check that feature
// and return feature result.
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
