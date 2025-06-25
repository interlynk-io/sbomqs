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

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo" // Added for lo.Contains
)

var (
	validBsiSpdxVersions      = []string{"SPDX-2.3"}
	validBsiCycloneDXVersions = []string{"1.4", "1.5", "1.6"}
)

// ComponentsListResult lists components or SBOM properties based on the specified features for multiple local SBOMs
func ComponentsListResult(ctx context.Context, ep *Params) (*Result, error) {
	log := logger.FromContext(ctx)
	log.Debug("list.ComponentsListResult()")

	// Process paths and generate results for each SBOM and feature
	results, err := processPaths(ctx, ep)
	if err != nil {
		log.Debugf("failed to process paths: %v", err)
		return nil, err
	}

	// Generate the report
	if err := generateReport(ctx, results, ep); err != nil {
		log.Debugf("failed to generate report: %v", err)
		return nil, err
	}

	// Return the first result for backward compatibility
	if len(results) > 0 {
		return results[0], nil
	}

	return nil, nil
}

// processPaths processes all local paths (files, directories) and generates ListResult for each SBOM and feature
func processPaths(ctx context.Context, ep *Params) ([]*Result, error) {
	log := logger.FromContext(ctx)
	var results []*Result

	for _, path := range ep.Path {
		// Get all file paths (handles files and directories)
		paths, err := getFilePaths(ctx, path)
		if err != nil {
			log.Debugf("failed to get file paths for %s: %v", path, err)
			continue
		}

		// Process each file path
		for _, filePath := range paths {
			// Parse the SBOM document
			currentDoc, err := parseSBOMDocument(ctx, filePath)
			if err != nil {
				log.Debugf("failed to parse SBOM document for %s: %v", filePath, err)
				continue
			}
			// Process each feature for the current SBOM
			for _, feature := range ep.Features {
				featureResult, err := processFeatureForSBOM(ctx, ep, currentDoc, filePath, feature)
				if err != nil {
					log.Debugf("failed to process feature %s for %s: %v", feature, filePath, err)
					continue
				}
				results = append(results, featureResult)
			}
		}
	}

	return results, nil
}

// getFilePaths returns a list of local file paths to process (handles files and directories)
func getFilePaths(ctx context.Context, path string) ([]string, error) {
	log := logger.FromContext(ctx)
	var paths []string

	log.Debugf("Processing path: %s", path)
	pathInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	if pathInfo.IsDir() {
		// Process all files in the directory
		files, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s: %w", path, err)
		}
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			filePath := filepath.Join(path, file.Name())
			paths = append(paths, filePath)
		}
	} else {
		// Single file
		paths = append(paths, path)
	}

	return paths, nil
}

// parseSBOMDocument parses an SBOM document from a local file path
func parseSBOMDocument(ctx context.Context, filePath string) (sbom.Document, error) {
	// log := logger.FromContext(ctx)

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()

	currentDoc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM document for %s: %w", filePath, err)
	}

	return currentDoc, nil
}

// processFeatureForSBOM processes a single feature for an SBOM document and returns a ListResult
func processFeatureForSBOM(ctx context.Context, ep *Params, doc sbom.Document, filePath, feature string) (*Result, error) {
	log := logger.FromContext(ctx)
	log.Debug("list.processFeatureForSBOM()")
	log.Debug("processing feature: ", feature)
	feature = strings.TrimSpace(feature)

	// Validate the feature
	if feature == "" {
		log.Debug("feature cannot be empty")
		return nil, fmt.Errorf("feature cannot be empty")
	}

	result := &Result{
		FilePath: filePath,
		Feature:  feature,
		Missing:  ep.Missing,
	}

	// Determine if the feature is component-based or SBOM-based
	if strings.HasPrefix(feature, "comp_") {
		return processComponentFeature(ctx, ep, doc, result)
	} else if strings.HasPrefix(feature, "sbom_") {
		return processSBOMFeature(ctx, ep, doc, result)
	}

	log.Debugf("feature %s must start with 'comp_' or 'sbom_'", feature)
	result.Errors = append(result.Errors, fmt.Sprintf("feature %s must start with 'comp_' or 'sbom_'", feature))
	return result, fmt.Errorf("feature %s must start with 'comp_' or 'sbom_'", feature)
}

// processComponentFeature processes a component-based feature for an SBOM document
func processComponentFeature(ctx context.Context, ep *Params, doc sbom.Document, result *Result) (*Result, error) {
	log := logger.FromContext(ctx)
	log.Debug("processing component feature: ", result.Feature)
	result.Components = []ComponentResult{}
	var totalComponents int

	// Evaluate the feature for each component
	for _, comp := range doc.Components() {
		log.Debugf("evaluating feature %s for component %s", result.Feature, comp.GetName())

		// Evaluate the feature for the component
		hasFeature, value, err := evaluateComponentFeature(result.Feature, comp, doc)
		if err != nil {
			log.Debugf("failed to evaluate feature %s for component: %v", result.Feature, err)
			result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for component: %v", result.Feature, err))
			continue
		}
		matchesCriteria := (hasFeature && !ep.Missing) || (!hasFeature && ep.Missing)
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

// processSBOMFeature processes an SBOM-based feature for an SBOM document
func processSBOMFeature(ctx context.Context, ep *Params, doc sbom.Document, result *Result) (*Result, error) {
	log := logger.FromContext(ctx)

	// SBOM-based feature
	hasFeature, value, err := evaluateSBOMFeature(result.Feature, doc)
	if err != nil {
		log.Debugf("failed to evaluate feature %s for document: %v", result.Feature, err)
		result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for document: %v", result.Feature, err))
		return result, err
	}

	matchesCriteria := (hasFeature && !ep.Missing) || (!hasFeature && ep.Missing)
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

// generateReport generates the report for the list command results
func generateReport(ctx context.Context, results []*Result, ep *Params) error {
	// log := logger.FromContext(ctx)

	reportFormat := "detailed"
	if ep.Basic {
		reportFormat = "basic"
	} else if ep.JSON {
		reportFormat = "json"
	}
	coloredOutput := ep.Color
	show := ep.Show

	lnr := NewListReport(ctx, results, WithFormat(strings.ToLower(reportFormat)), WithColor(coloredOutput), WithValues(show))
	lnr.Report()
	return nil
}

// evaluateComponentFeature evaluates a component-based feature for a single component
func evaluateComponentFeature(feature string, comp sbom.GetComponent, doc sbom.Document) (bool, string, error) {
	switch feature {

	case "comp_with_name":
		return evaluateCompWithName(comp)

	case "comp_with_version":
		return evaluateCompWithVersion(comp)

	case "comp_with_supplier":
		return evaluateCompWithSupplier(comp)

	case "comp_with_uniq_ids":
		return evaluateCompWithUniqID(comp)

	case "comp_valid_licenses":
		return evaluateCompWithValidLicenses(comp)

	case "comp_with_checksums_sha256":
		return evaluateCompWithSHA256Checksums(comp)

	case "comp_with_source_code_uri":
		return evaluateCompWithSourceCodeURI(doc, comp)

	case "comp_with_source_code_hash":
		return evaluateCompWithSourceCodeHash(doc, comp)

	case "comp_with_executable_uri":
		return evaluateCompWithExecutableURI(comp)

	// case "comp_with_executable_hash":
	// 	return evaluateCompWithExecutableHash(comp)

	case "comp_with_associated_license":
		return evaluateCompWithAssociatedLicense(doc, comp)

	case "comp_with_concluded_license":
		return evaluateCompWithConcludedLicense(doc, comp)

	case "comp_with_declared_license":
		return evaluateCompWithDeclaredLicense(doc, comp)

	case "comp_with_dependencies":
		return evaluateCompWithDependencies(doc, comp)

	case "comp_with_any_vuln_lookup_id":
		return evaluateCompWithAnyVulnLookupID(comp)

	case "comp_with_deprecated_licenses":
		return evaluateCompWithDeprecatedLicenses(comp)

	case "comp_with_multi_vuln_lookup_id":
		return evaluateCompWithMultiVulnLookupID(comp)

	case "comp_with_primary_purpose":
		return evaluateCompWithPrimaryPurpose(doc, comp)

	case "comp_with_restrictive_licenses":
		return evaluateCompWithRestrictedLicenses(doc, comp)

	case "comp_with_checksums":
		return evaluateCompWithChecksums(comp)

	case "comp_with_licenses":
		return evaluateCompWithLicenses(comp)

	default:
		return false, "", fmt.Errorf("unsupported component feature: %s", feature)
	}
}

// evaluateSBOMFeature evaluates an SBOM-based feature for the document
func evaluateSBOMFeature(feature string, doc sbom.Document) (bool, string, error) {
	switch feature {

	case "sbom_creation_timestamp":
		timestamp := doc.Spec().GetCreationTimestamp()
		return timestamp != "", timestamp, nil

	case "sbom_authors":
		return evaluateSBOMAuthors(doc)

	case "sbom_with_creator_and_version":
		return evaluateSBOMWithCreatorAndVersion(doc)

	case "sbom_with_primary_component":
		return evaluateSBOMPrimaryComponent(doc)

	case "sbom_dependencies":
		return evaluateSBOMDependencies(doc)

	case "sbom_sharable":
		return evaluateSBOMSharable(doc)

	case "sbom_parsable":
		return evaluateSBOMParsable(doc)

	case "sbom_spec":
		return evaluateSBOMSpec(doc)

	case "sbom_spec_file_format":
		return evaluateSBOMSpecFileFormat(doc)

	case "sbom_spec_version":
		return evaluateSBOMSpecVersion(doc)

	case "spec_with_version_compliant":
		return evaluateSBOMSpecVersionCompliant(doc)

	case "sbom_with_uri":
		return evaluateSBOMWithURI(doc)

	case "sbom_with_vuln":
		return evaluateSBOMWithVulnerability(doc)

	case "sbom_build_process":
		return evaluateSBOMBuildLifeCycle(doc)

	case "sbom_with_bomlinks":
		return evaluateSBOMWithBomLinks(doc)

	// case "sbom_with_signature":
	// 	return evaluateSBOMWithSignature(doc)

	default:
		return false, "", fmt.Errorf("unsupported SBOM feature: %s", feature)
	}
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

// evaluate comp with name
func evaluateCompWithName(comp sbom.GetComponent) (bool, string, error) {
	return comp.GetName() != "", comp.GetName(), nil
}

// evaluateCompWithVersion evaluates if the component has a version
func evaluateCompWithVersion(comp sbom.GetComponent) (bool, string, error) {
	return comp.GetVersion() != "", comp.GetVersion(), nil
}

// evaluateCompWithSupplier evaluates if the component has a supplier
func evaluateCompWithSupplier(comp sbom.GetComponent) (bool, string, error) {
	return comp.Suppliers().IsPresent(), comp.Suppliers().GetName() + "," + comp.Suppliers().GetEmail(), nil
}

// evaluateCompWithUniqID evaluates if the component has a unique ID
func evaluateCompWithUniqID(comp sbom.GetComponent) (bool, string, error) {
	return comp.GetID() != "", comp.GetID(), nil
}

// evaluateCompWithValidLicenses evaluates if the component has valid licenses
func evaluateCompWithValidLicenses(comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.Licenses()
	if len(licenses) == 0 {
		return false, "", nil
	}

	validLicenses := make([]string, 0, len(licenses))
	for _, l := range licenses {
		if l != nil && l.Spdx() {
			validLicenses = append(validLicenses, l.Name())
		}
	}

	if len(validLicenses) == 0 {
		return false, "", nil
	}
	return true, strings.Join(validLicenses, ","), nil
}

// evaluateCompWithAnyVulnLookupID evaluates if the component has any vulnerability lookup ID
func evaluateCompWithAnyVulnLookupID(comp sbom.GetComponent) (bool, string, error) {
	cpes := comp.GetCpes()
	purls := comp.GetPurls()

	if len(cpes) == 0 || len(purls) == 0 {
		return false, "", nil
	}

	allIDs := make([]string, 0, len(cpes)+len(purls))
	for _, cpe := range cpes {
		allIDs = append(allIDs, cpe.String()) // Assuming cpe.CPE has a String() method
	}
	for _, purl := range purls {
		allIDs = append(allIDs, purl.String()) // Assuming purl.PURL has a String() method
	}

	return true, strings.Join(allIDs, ","), nil
}

// evaluateCompWithMultiVulnLookupID evaluates if the component has multiple vulnerability lookup IDs
func evaluateCompWithMultiVulnLookupID(comp sbom.GetComponent) (bool, string, error) {
	cpes := comp.GetCpes()
	purls := comp.GetPurls()

	hasFeature := len(cpes) > 0 && len(purls) > 0

	if len(cpes) == 0 && len(purls) == 0 {
		return false, "", nil
	}

	allIDs := make([]string, 0, len(cpes)+len(purls))
	for _, cpe := range cpes {
		allIDs = append(allIDs, cpe.String()) // Assuming cpe.CPE has a String() method
	}
	for _, purl := range purls {
		allIDs = append(allIDs, purl.String()) // Assuming purl.PURL has a String() method
	}

	return hasFeature, strings.Join(allIDs, ","), nil
}

// evaluateCompWithDeprecatedLicenses evaluates if the component has any deprecated licenses
func evaluateCompWithDeprecatedLicenses(comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.Licenses()
	if len(licenses) == 0 {
		return false, "", nil
	}

	deprecatedLicenses := make([]string, 0, len(licenses))
	licenseNames := make([]string, 0, len(licenses))

	for _, l := range licenses {
		if l != nil {
			licenseNames = append(licenseNames, l.Name())
			if l.Deprecated() {
				deprecatedLicenses = append(deprecatedLicenses, l.Name())
			}
		}
	}

	if len(deprecatedLicenses) == 0 {
		return false, strings.Join(licenseNames, ","), nil
	}
	return true, strings.Join(deprecatedLicenses, ","), nil
}

// evaluateCompWithPrimaryPurpose evaluates if the component has a primary purpose
func evaluateCompWithPrimaryPurpose(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	purpose := comp.PrimaryPurpose()
	hasFeature := purpose != "" && lo.Contains(sbom.SupportedPrimaryPurpose(doc.Spec().GetSpecType()), strings.ToLower(purpose))
	return hasFeature, purpose, nil
}

// evaluateCompWithRestrictedLicenses evaluates if the component has any restrictive licenses
func evaluateCompWithRestrictedLicenses(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.Licenses()
	if len(licenses) == 0 {
		return false, "", nil
	}

	restrictiveLicenses := make([]string, 0, len(licenses))
	licenseNames := make([]string, 0, len(licenses))

	for _, l := range licenses {
		if l != nil {
			licenseNames = append(licenseNames, l.Name())
			if l.Restrictive() {
				restrictiveLicenses = append(restrictiveLicenses, l.Name())
			}
		}
	}

	if len(restrictiveLicenses) == 0 {
		return false, strings.Join(licenseNames, ","), nil
	}

	return true, strings.Join(restrictiveLicenses, ","), nil
}

// evaluateCompWithChecksums evaluates if the component has checksums
func evaluateCompWithChecksums(comp sbom.GetComponent) (bool, string, error) {
	checksums := comp.GetChecksums()
	if len(checksums) == 0 {
		return false, "", nil
	}

	checksumValues := make([]string, 0, len(checksums))
	for _, checksum := range checksums {
		checksumValues = append(checksumValues, checksum.GetAlgo()) // Assuming sbom.GetChecksum has a GetAlgo() method
	}
	return true, strings.Join(checksumValues, ","), nil
}

// evaluateCompWithLicenses
func evaluateCompWithLicenses(comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.Licenses()
	if len(licenses) == 0 {
		return false, "", nil
	}

	licenseNames := make([]string, 0, len(licenses))
	for _, l := range licenses {
		if l != nil {
			licenseNames = append(licenseNames, l.Name())
		}
	}

	return true, strings.Join(licenseNames, ","), nil
}

// evaluateCompWithSHA256Checksums evaluates if the component has SHA-256 checksums
func evaluateCompWithSHA256Checksums(comp sbom.GetComponent) (bool, string, error) {
	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}

	checksums := comp.GetChecksums()
	if len(checksums) == 0 {
		return false, "", nil
	}

	sha256Checksums := make([]string, 0, len(checksums))
	for _, checksum := range checksums {
		if lo.Contains(algos, checksum.GetAlgo()) {
			sha256Checksums = append(sha256Checksums, checksum.GetAlgo()) // Assuming sbom.GetChecksum has a GetValue() method
		}
	}

	if len(sha256Checksums) == 0 {
		return false, "", nil
	}
	return true, strings.Join(sha256Checksums, ","), nil
}

// evaluateCompWithSourceCodeURI evaluates if the component has a source code URI
func evaluateCompWithSourceCodeURI(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	if doc.Spec().GetSpecType() == "spdx" {
		return false, "source code URI is not supported for SPDX documents", nil
	}

	sourceCodeURI := comp.SourceCodeURL()
	if sourceCodeURI != "" {
		return true, sourceCodeURI, nil
	}
	return false, "", nil
}

// evaluateCompWithSourceCodeHash evaluates if the component has a source code hash
func evaluateCompWithSourceCodeHash(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	if doc.Spec().GetSpecType() == "cyclonedx" {
		return false, "no-deterministic-field in cdx", nil
	}

	sourceCodeHash := comp.SourceCodeHash()
	if sourceCodeHash != "" {
		return true, sourceCodeHash, nil
	}
	return false, "", nil
}

// evaluateCompWithExecutableURI evaluates if the component has an executable URI
func evaluateCompWithExecutableURI(comp sbom.GetComponent) (bool, string, error) {
	executableURI := comp.GetDownloadLocationURL()
	if executableURI != "" {
		return true, executableURI, nil
	}
	return false, "", nil
}

// evaluateCompWithAssociatedLicense evaluates if the component has an associated license
func evaluateCompWithAssociatedLicense(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	// associatedLicense := comp.AssociatedLicense()
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		var associatedLicense []string
		for _, l := range comp.ConcludedLicenses() {
			if l != nil {
				associatedLicense = append(associatedLicense, l.Name())
			}
		}

		if len(associatedLicense) == 0 {
			return false, "", nil
		}
		return true, strings.Join(associatedLicense, ","), nil
	} else if spec == "cyclonedx" {
		var associatedLicense []string

		for _, l := range comp.Licenses() {
			if l != nil {
				associatedLicense = append(associatedLicense, l.Name())
			}
		}

		if len(associatedLicense) == 0 {
			return false, "", nil
		}
		return true, strings.Join(associatedLicense, ","), nil
	}
	return false, "", nil
}

// evaluateCompWithConcludedLicense evaluates if the component has a concluded license
func evaluateCompWithConcludedLicense(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var concludedLicense []string
	for _, l := range comp.ConcludedLicenses() {
		if l != nil {
			concludedLicense = append(concludedLicense, l.Name())
		}
	}

	if len(concludedLicense) == 0 {
		return false, "", nil
	}
	return true, strings.Join(concludedLicense, ","), nil
}

// evaluateCompWithDeclaredLicense evaluates if the component has a declared license
func evaluateCompWithDeclaredLicense(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var declaredLicense []string
	for _, l := range comp.DeclaredLicenses() {
		if l != nil {
			declaredLicense = append(declaredLicense, l.Name())
		}
	}

	if len(declaredLicense) == 0 {
		return false, "", nil
	}
	return true, strings.Join(declaredLicense, ","), nil
}

// evaluateCompWithDependencies evaluates if the component has dependencies
func evaluateCompWithDependencies(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	if comp == nil {
		return false, "", fmt.Errorf("component is nil")
	}

	dependencies := comp.HasRelationShips()
	if !dependencies {
		return false, "no-dependencies", nil
	}

	return true, "contains dependencies", nil
}

// evaluateSBOMAuthors evaluates if the SBOM has authors
func evaluateSBOMAuthors(doc sbom.Document) (bool, string, error) {
	authors := doc.Authors()
	if len(authors) == 0 {
		return false, "", nil
	}

	authorNames := make([]string, 0, len(authors))
	for _, author := range authors {
		if author != nil {
			if author.GetEmail() != "" {
				authorNames = append(authorNames, author.GetName()+","+author.GetEmail())
			} else {
				authorNames = append(authorNames, author.GetName())
			}
		}
	}

	return true, strings.Join(authorNames, ", "), nil
}

// evaluateSBOMWithCreatorAndVersion evaluates if the SBOM has a creator and version
func evaluateSBOMWithCreatorAndVersion(doc sbom.Document) (bool, string, error) {
	if len(doc.Tools()) > 0 {
		tool := doc.Tools()[0]
		value := fmt.Sprintf("%s v%s", tool.GetName(), tool.GetVersion())
		return true, value, nil
	}
	return false, "", nil
}

// evaluateSBOMPrimaryComponent evaluates if the SBOM has a primary component
func evaluateSBOMPrimaryComponent(doc sbom.Document) (bool, string, error) {
	if doc.PrimaryComp() != nil {
		value := fmt.Sprintf("%s v%s", doc.PrimaryComp().GetName(), doc.PrimaryComp().GetVersion())
		return true, value, nil
	}
	return false, "", nil
}

// evaluateSBOMDependencies evaluates if the SBOM has dependencies
func evaluateSBOMDependencies(doc sbom.Document) (bool, string, error) {
	if doc.PrimaryComp() != nil {
		count := doc.PrimaryComp().GetTotalNoOfDependencies()
		values := doc.PrimaryComp().GetDependencies()
		if count > 0 {
			return true, fmt.Sprintf("%d dependencies: %s", count, strings.Join(values, ", ")), nil
		}
	}
	return false, "", nil
}

// evaluateSBOMSharable evaluates if the SBOM is sharable
func evaluateSBOMSharable(doc sbom.Document) (bool, string, error) {
	lics := doc.Spec().GetLicenses()
	if len(lics) == 0 {
		return false, "", nil
	}
	licenseNames := make([]string, 0, len(lics))
	freeLicCount := 0
	for _, l := range lics {
		if l != nil {
			licenseNames = append(licenseNames, l.Name())
			if l.FreeAnyUse() {
				freeLicCount++
			}
		}
	}
	if freeLicCount > 0 {
		return true, fmt.Sprintf("Sharable under licenses: %s", strings.Join(licenseNames, ", ")), nil
	}
	return false, "", nil
}

// evaluateSBOMParsable evaluates if the SBOM is parsable
func evaluateSBOMParsable(doc sbom.Document) (bool, string, error) {
	if doc.Spec().Parsable() {
		return true, "SBOM is parsable", nil
	}
	return false, "SBOM is not parsable", nil
}

// evaluateSBOMSpec evaluates if the SBOM has a specification
func evaluateSBOMSpec(doc sbom.Document) (bool, string, error) {
	specType := doc.Spec().GetSpecType()
	if specType != "" {
		return true, specType, nil
	}
	return false, "", nil
}

// evaluateSBOMSpecFileFormat evaluates if the SBOM has a file format
func evaluateSBOMSpecFileFormat(doc sbom.Document) (bool, string, error) {
	fileFormat := doc.Spec().FileFormat()
	if fileFormat != "" {
		return true, fileFormat, nil
	}
	return false, "", nil
}

// evaluateSBOMSpecVersion evaluates if the SBOM has a specification version
func evaluateSBOMSpecVersion(doc sbom.Document) (bool, string, error) {
	version := doc.Spec().GetVersion()
	if version != "" {
		return true, version, nil
	}
	return false, "", nil
}

// evaluateSBOMSpecVersionCompliant evaluates if the SBOM specification version is compliant
func evaluateSBOMSpecVersionCompliant(doc sbom.Document) (bool, string, error) {
	specVersion := doc.Spec().GetVersion()
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		count := lo.Count(validBsiSpdxVersions, specVersion)
		if count == 0 {
			return false, "", fmt.Errorf("SBOM spec version %s is not compliant with BSI SPDX versions", specVersion)
		}
		return true, specVersion, nil
	} else if spec == "cyclonedx" {

		count := lo.Count(validBsiCycloneDXVersions, specVersion)
		if count == 0 {
			return false, "", fmt.Errorf("SBOM spec version %s is not compliant with CycloneDX versions", specVersion)
		}
		return true, specVersion, nil
	}

	return false, "", nil
}

// evaluateSBOMWithURI evaluates if the SBOM has a URI
func evaluateSBOMWithURI(doc sbom.Document) (bool, string, error) {
	uri := doc.Spec().GetURI()
	if uri != "" {
		return true, uri, nil
	}
	return false, "", nil
}

// evaluateSBOMWithVulnerability evaluates if the SBOM has any vulnerabilities
func evaluateSBOMWithVulnerability(doc sbom.Document) (bool, string, error) {
	if doc.Spec().GetSpecType() == "spdx" {
		return true, "", nil
	}

	vulns := doc.Vulnerabilities()

	if len(vulns) == 0 {
		return true, "", nil
	}

	var allVulnIDs []string
	for _, v := range vulns {
		if vulnID := v.GetID(); vulnID != "" {
			allVulnIDs = append(allVulnIDs, vulnID)
		}
	}

	return false, strings.Join(allVulnIDs, ", "), nil
}

// evaluateSBOMBuildProcess evaluates if the SBOM has a build process
func evaluateSBOMBuildLifeCycle(doc sbom.Document) (bool, string, error) {
	if doc.Spec().GetSpecType() == "spdx" {
		return false, "no-deterministic-field in spdx", nil
	}

	lifecycles := doc.Lifecycles()
	found := lo.Count(lifecycles, "build")
	if found == 0 {
		return false, "no build lifecycle found", nil
	}

	return true, lifecycles[found-1], nil
}

// evaluateSBOMWithBomLinks evaluates if the SBOM has BOM links
func evaluateSBOMWithBomLinks(doc sbom.Document) (bool, string, error) {
	bomLinks := doc.Spec().GetExtDocRef()
	if len(bomLinks) == 0 {
		return false, "", nil
	}

	linkValues := make([]string, 0, len(bomLinks))
	linkValues = append(linkValues, bomLinks...)

	return true, strings.Join(linkValues, ", "), nil
}
