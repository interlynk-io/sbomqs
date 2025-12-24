// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package list

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"go.uber.org/zap"
)

var (
	validBsiSpdxVersions      = []string{"SPDX-2.3"}
	validBsiCycloneDXVersions = []string{"1.4", "1.5", "1.6"}
)

// ComponentsListResult lists components or SBOM properties based on the specified features for multiple local SBOMs
func ComponentsListResult(ctx context.Context, ep *Params) (*Result, error) {
	log := logger.FromContext(ctx)

	log.Info("Starting SBOM list operation",
		zap.Strings("paths", ep.Path),
		zap.Strings("features", ep.Features),
	)

	results, err := collectResultsForInputPaths(ctx, ep)
	if err != nil {
		log.Error("Failed to collect results for input paths",
			zap.Error(err),
		)
		return nil, err
	}

	log.Debug("Collected list results",
		zap.Int("result_count", len(results)),
	)

	if err := generateReport(ctx, results, ep); err != nil {
		log.Error("Failed to generate list report",
			zap.Error(err),
		)
		return nil, err
	}

	if len(results) > 0 {
		log.Info("SBOM list operation completed successfully",
			zap.Int("result_count", len(results)),
		)
		return results[0], nil
	}

	log.Warn("SBOM list operation completed with no results")
	return nil, nil
}

// collectResultsForInputPaths
func collectResultsForInputPaths(ctx context.Context, ep *Params) ([]*Result, error) {
	log := logger.FromContext(ctx)

	log.Debug("Resolving input paths",
		zap.Strings("paths", ep.Path),
	)

	filePaths, err := expandPathsToFiles(ctx, ep.Path)
	if err != nil {
		log.Error("Failed to expand input paths",
			zap.Error(err),
		)
		return nil, err
	}

	log.Debug("Expanded input paths to files",
		zap.Int("file_count", len(filePaths)),
	)

	return collectResultsForSBOMs(ctx, ep, filePaths)
}

// expandPathsToFiles resolves a mix of files/directories into concrete SBOM file paths.
func expandPathsToFiles(ctx context.Context, paths []string) ([]string, error) {
	log := logger.FromContext(ctx)
	log.Debug("Exapmading provided paths into files", zap.Strings("paths", paths))

	var files []string
	for _, p := range paths {
		fps, err := filesFromPath(ctx, p)
		if err != nil {
			log.Warn("Skipping path due to error",
				zap.String("path", p),
				zap.Error(err),
			)
			continue
		}
		files = append(files, fps...)
	}

	if len(files) == 0 {
		log.Warn("No SBOM files found after path expansion")
	}
	return files, nil
}

// filesFromPath returns a list of local file paths to process (handles files and directories)
func filesFromPath(ctx context.Context, path string) ([]string, error) {
	log := logger.FromContext(ctx)
	var paths []string

	log.Debug("Processing input path",
		zap.String("path", path),
	)
	pathInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	if pathInfo.IsDir() {
		files, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			paths = append(paths, filepath.Join(path, file.Name()))
		}

		log.Debug("Directory expanded",
			zap.String("path", path),
			zap.Int("file_count", len(paths)),
		)
	} else {
		paths = append(paths, path)
	}

	return paths, nil
}

// collectResultsForSBOMs parses each SBOM file and evaluates all requested features.
func collectResultsForSBOMs(ctx context.Context, ep *Params, filePaths []string) ([]*Result, error) {
	log := logger.FromContext(ctx)

	var results []*Result

	for _, filePath := range filePaths {
		fileResults, err := collectResultsForSBOM(ctx, ep, filePath)
		if err != nil {
			log.Warn("Skipping SBOM file due to error",
				zap.String("file", filePath),
				zap.Error(err),
			)
			continue
		}
		results = append(results, fileResults...)
	}

	return results, nil
}

// collectResultsForFile parses a single SBOM file and evaluates all requested features.
func collectResultsForSBOM(ctx context.Context, ep *Params, filePath string) ([]*Result, error) {
	log := logger.FromContext(ctx)

	doc, err := parseSBOMDocument(ctx, filePath)
	if err != nil {
		log.Error("Failed to parse SBOM document",
			zap.String("file", filePath),
			zap.Error(err),
		)
		return nil, err
	}

	var results []*Result
	for _, rawFeature := range ep.Features {
		feature := strings.TrimSpace(rawFeature)
		log.Debug("Evaluating feature",
			zap.String("feature", feature),
			zap.String("file", filePath),
		)

		res, err := evaluateFeature(ctx, ep.Missing, doc, filePath, feature)
		if err != nil {
			log.Warn("Feature evaluation failed",
				zap.String("feature", feature),
				zap.String("file", filePath),
				zap.Error(err),
			)
			continue
		}
		results = append(results, res)
	}

	return results, nil
}

// parseSBOMDocument parses an SBOM document from a local file path
func parseSBOMDocument(ctx context.Context, filePath string) (sbom.Document, error) {
	log := logger.FromContext(ctx)
	log.Debug("Opening SBOM file",
		zap.String("file", filePath),
	)
	// #nosec G304 -- User-provided paths are expected for CLI tool
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warn("Failed to close SBOM file",
				zap.String("file", filePath),
				zap.Error(err),
			)
		}
	}()

	currentDoc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM document for %s: %w", filePath, err)
	}

	log.Debug("SBOM document parsed successfully",
		zap.String("file", filePath),
	)
	return currentDoc, nil
}

// evaluateFeature processes a single feature for an SBOM document and returns a ListResult
func evaluateFeature(ctx context.Context, missing bool, doc sbom.Document, filePath, feature string) (*Result, error) {
	log := logger.FromContext(ctx)
	feature = strings.TrimSpace(feature)

	if feature == "" {
		log.Debug("feature cannot be empty")
		return nil, fmt.Errorf("feature cannot be empty")
	}

	log.Debug("Evaluating feature for SBOM",
		zap.String("feature", feature),
		zap.String("file", filePath),
	)

	switch {

	case strings.HasPrefix(feature, "comp_"):
		return evaluateFeatureForComponent(ctx, doc, filePath, feature, missing)

	case strings.HasPrefix(feature, "sbom_"):
		return evaluateFeatureForDocument(ctx, doc, filePath, feature, missing)

	default:
		msg := fmt.Sprintf("feature %s must start with 'comp_' or 'sbom_'", feature)
		return nil, fmt.Errorf("%s", msg)
	}
}

// evaluateFeatureForComponent evaluates a component-based feature across all components.
func evaluateFeatureForComponent(ctx context.Context, doc sbom.Document, filePath, feature string, missing bool) (*Result, error) {
	log := logger.FromContext(ctx)

	result := &Result{
		FilePath: filePath,
		Feature:  feature,
		Missing:  missing,
	}

	result.Components = []ComponentResult{}
	var totalComponents int

	for _, comp := range doc.Components() {
		log.Debug("evaluating feature for component", zap.String("feature", result.Feature), zap.String("comp", comp.GetName()))

		hasFeature, value, err := evaluateFeaturePerComponent(result.Feature, comp, doc)
		if err != nil {
			log.Debug("Component feature evaluation failed",
				zap.String("feature", feature),
				zap.String("component", comp.GetName()),
				zap.Error(err),
			)
			result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for component: %v", result.Feature, err))
			continue
		}

		matchesCriteria := (hasFeature && !missing) || (!hasFeature && missing)
		if matchesCriteria {
			result.Components = append(result.Components, ComponentResult{
				Name:    comp.GetName(),
				Version: comp.GetVersion(),
				Values:  value,
			})
		}

		totalComponents++
	}
	result.TotalComponents = totalComponents
	return result, nil
}

// evaluateFeatureForDocument evaluates an SBOM-based feature for the SBOM document.
func evaluateFeatureForDocument(ctx context.Context, doc sbom.Document, filePath, feature string, missing bool) (*Result, error) {
	log := logger.FromContext(ctx)

	result := &Result{
		FilePath: filePath,
		Feature:  feature,
		Missing:  missing,
	}

	// SBOM-based feature
	hasFeature, value, err := evaluateSBOMFeature(result.Feature, doc)
	if err != nil {
		log.Debug("SBOM feature evaluation failed",
			zap.String("feature", feature),
			zap.Error(err),
		)
		result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for document: %v", result.Feature, err))
		return result, err
	}

	matchesCriteria := (hasFeature && !missing) || (!hasFeature && missing)
	result.DocumentProperty = DocumentResult{
		Key:     featureToPropertyName(result.Feature),
		Present: hasFeature,
		Value:   value,
	}

	if matchesCriteria {
		if hasFeature {
			result.DocumentProperty.Value = value
		} else {
			result.DocumentProperty.Value = "Not present"
		}
	}

	return result, nil
}

// evaluateFeaturePerComponent evaluates a component-based feature for a single component
func evaluateFeaturePerComponent(feature string, comp sbom.GetComponent, doc sbom.Document) (bool, string, error) {
	// resolve aliases
	if f, ok := compFeatureAliases[feature]; ok {
		feature = f
	}

	eval, ok := compFeatureRegistry[feature]
	if !ok {
		return false, "", fmt.Errorf("unsupported component feature: %s", feature)
	}

	return eval(comp, doc)
}

// evaluateSBOMFeature evaluates an SBOM-based feature for the document
func evaluateSBOMFeature(feature string, doc sbom.Document) (bool, string, error) {
	// resolve alias
	if f, ok := sbomFeatureAliases[feature]; ok {
		feature = f
	}

	eval, ok := sbomFeatureRegistry[feature]
	if !ok {
		return false, "", fmt.Errorf("unsupported SBOM feature: %s", feature)
	}

	return eval(doc)
}

// generateReport generates the report for the list command results
func generateReport(ctx context.Context, results []*Result, ep *Params) error {
	log := logger.FromContext(ctx)

	reportFormat := common.ReportDetailed
	if ep.Basic {
		reportFormat = common.ReportBasic
	} else if ep.JSON {
		reportFormat = common.FormatJSON
	}

	log.Info("Generating list report",
		zap.String("format", reportFormat),
		zap.Bool("color", ep.Color),
		zap.Int("results", len(results)),
	)

	lnr := NewListReport(ctx, results, WithFormat(strings.ToLower(reportFormat)), WithColor(ep.Color), WithValues(ep.Show))
	lnr.Report()

	return nil
}

// featureToPropertyName converts a feature name to a human-readable property name
func featureToPropertyName(feature string) string {
	switch feature {

	case "sbom_creation_timestamp":
		return "Creation Timestamp"

	case "sbom_authors":
		return "Authors"

	case "sbom_with_creator_and_version":
		return "Creator and Version"

	case "sbom_with_primary_component":
		return "Primary Component and Version"

	case "sbom_dependencies":
		return "Dependencies"

	case "sbom_required_fields":
		return "Required Fields"

	case "sbom_sharable":
		return "Sharable License"

	case "sbom_parsable":
		return "Parsable"

	case "sbom_spec":
		return "Specification"

	case "sbom_spec_file_format":
		return "File Format"

	case "sbom_spec_version":
		return "Spec Version"

	default:
		return strings.ReplaceAll(strings.TrimPrefix(feature, "sbom_"), "_", " ")
	}
}
