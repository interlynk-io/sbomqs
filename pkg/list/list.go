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
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo" // Added for lo.Contains
)

func ComponentsListResult(ctx context.Context, ep ListParams, doc sbom.Document) (*ListResult, error) {
	log := logger.FromContext(ctx)
	log.Debug("list.ComponentsListResult()")

	result := &ListResult{
		FilePath: ep.Path[0],
		Missing:  ep.Missing,
	}

	if doc == nil {
		log.Debugf("sbom document is nil\n")
		return result, fmt.Errorf("sbom document is nil")
	}

	// Validate the feature
	if len(ep.Features) != 1 {
		log.Debug("exactly one feature must be specified")
		result.Errors = append(result.Errors, "exactly one feature must be specified")
		return result, fmt.Errorf("exactly one feature must be specified")
	}

	feature := ep.Features[0]

	result.Feature = feature

	// determine if the feature is component-based or SBOM-based
	if strings.HasPrefix(feature, "comp_") {

		// component-based feature
		result.Components = []ComponentResult{}
		var totalComponents int

		// evaluate the feature for each component
		for _, comp := range doc.Components() {
			log.Debugf("evaluating feature %s for component %s", feature, comp.GetName())

			// evaluate the feature for the component
			hasFeature, value, err := evaluateComponentFeature(feature, comp, doc)
			if err != nil {
				log.Debugf("failed to evaluate feature %s for component: %v", feature, err)
				result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for component: %v", feature, err))
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

	} else if strings.HasPrefix(feature, "sbom_") {

		// SBOM-based feature
		hasFeature, value, err := evaluateSBOMFeature(feature, doc)
		if err != nil {
			log.Debugf("failed to evaluate feature %s for document: %v", feature, err)
			result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for document: %v", feature, err))
			return result, err
		}

		matchesCriteria := (hasFeature && !ep.Missing) || (!hasFeature && ep.Missing)
		result.DocumentProperty = DocumentResult{
			Key:     featureToPropertyName(feature),
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
	} else {
		log.Debugf("feature %s must start with 'comp_' or 'sbom_'", feature)
		result.Errors = append(result.Errors, fmt.Sprintf("feature %s must start with 'comp_' or 'sbom_'", feature))
		return result, fmt.Errorf("feature %s must start with 'comp_' or 'sbom_'", feature)
	}

	reportFormat := "basic"
	if ep.Detailed {
		reportFormat = "detailed"
	} else if ep.JSON {
		reportFormat = "json"
	}
	coloredOutput := ep.Color

	var listResult []*ListResult
	listResult = append(listResult, result)
	// lnr := NewListReport(ctx, listResult, WithFormat(strings.ToLower(reportFormat)), WithColor(coloredOutput))
	lnr := NewListReport(ctx, listResult, WithFormat(strings.ToLower(reportFormat)), WithColor(coloredOutput))

	lnr.Report()
	return result, nil
}

// evaluateComponentFeature evaluates a component-based feature for a single component
func evaluateComponentFeature(feature string, comp sbom.GetComponent, doc sbom.Document) (bool, string, error) {
	switch feature {

	case "comp_with_name":
		return comp.GetName() != "", comp.GetName(), nil

	case "comp_with_version":
		return comp.GetVersion() != "", comp.GetVersion(), nil

	case "comp_with_supplier":
		return comp.Suppliers().IsPresent(), comp.Suppliers().GetName(), nil

	case "comp_with_uniq_ids":
		return comp.GetID() != "", comp.GetID(), nil

	case "comp_valid_licenses":
		licenses := comp.Licenses()
		if len(licenses) == 0 {
			return false, "", nil
		}

		// check if at least one license is a valid SPDX license
		for _, l := range licenses {
			if l != nil && l.Spdx() {
				return true, l.Name(), nil
			}
		}
		return false, "", nil

	case "comp_with_any_vuln_lookup_id":
		cpes := comp.GetCpes()
		purls := comp.GetPurls()
		hasFeature := len(cpes) > 0 || len(purls) > 0
		value := ""
		if hasFeature {
			allIDs := make([]string, 0, len(cpes)+len(purls))
			for _, cpe := range cpes {
				allIDs = append(allIDs, cpe.String()) // Assuming cpe.CPE has a String() method
			}
			for _, purl := range purls {
				allIDs = append(allIDs, purl.String()) // Assuming purl.PURL has a String() method
			}
			value = strings.Join(allIDs, ",")
		}
		return hasFeature, value, nil

	case "comp_with_deprecated_licenses":
		licenses := comp.Licenses()
		if len(licenses) == 0 {
			return false, "", nil
		}
		deprecatedLicenses := []string{}
		licenseNames := make([]string, 0, len(licenses))
		for _, l := range licenses {
			if l != nil {
				licenseNames = append(licenseNames, l.Name())
				if l.Deprecated() {
					deprecatedLicenses = append(deprecatedLicenses, l.Name())
				}
			}
		}
		hasFeature := len(deprecatedLicenses) > 0
		value := ""
		if hasFeature {
			value = strings.Join(deprecatedLicenses, ",")
		} else {
			value = strings.Join(licenseNames, ",")
		}
		return hasFeature, value, nil

	case "comp_with_multi_vuln_lookup_id":
		cpes := comp.GetCpes()
		purls := comp.GetPurls()
		hasFeature := len(cpes) > 0 && len(purls) > 0
		value := ""
		if hasFeature {
			allIDs := make([]string, 0, len(cpes)+len(purls))
			for _, cpe := range cpes {
				allIDs = append(allIDs, cpe.String()) // Assuming cpe.CPE has a String() method
			}
			for _, purl := range purls {
				allIDs = append(allIDs, purl.String()) // Assuming purl.PURL has a String() method
			}
			value = strings.Join(allIDs, ",")
		}
		return hasFeature, value, nil

	case "comp_with_primary_purpose":
		purpose := comp.PrimaryPurpose()
		hasFeature := purpose != "" && lo.Contains(sbom.SupportedPrimaryPurpose(doc.Spec().GetSpecType()), strings.ToLower(purpose))
		return hasFeature, purpose, nil

	case "comp_with_restrictive_licenses":
		licenses := comp.Licenses()
		if len(licenses) == 0 {
			return false, "", nil
		}
		restrictiveLicenses := []string{}
		licenseNames := make([]string, 0, len(licenses))

		for _, l := range licenses {
			if l != nil {
				licenseNames = append(licenseNames, l.Name())
				if l.Restrictive() {
					restrictiveLicenses = append(restrictiveLicenses, l.Name())
				}
			}
		}
		hasFeature := len(restrictiveLicenses) > 0
		value := ""
		if hasFeature {
			value = strings.Join(restrictiveLicenses, ",")
		} else {
			value = strings.Join(licenseNames, ",")
		}
		return hasFeature, value, nil

	case "comp_with_checksums":
		checksums := comp.GetChecksums()
		hasFeature := len(checksums) > 0
		value := ""
		if hasFeature {
			checksumValues := make([]string, 0, len(checksums))
			for _, checksum := range checksums {
				checksumValues = append(checksumValues, checksum.GetAlgo()) // Assuming sbom.GetChecksum has a Value() method
			}
			value = strings.Join(checksumValues, ",")
		}
		return hasFeature, value, nil

	case "comp_with_licenses":
		licenses := comp.Licenses()
		hasFeature := len(licenses) > 0
		licenseNames := make([]string, 0, len(licenses))

		for _, l := range licenses {
			licenseNames = append(licenseNames, l.Name())
		}
		value := ""
		if hasFeature {
			value = strings.Join(licenseNames, ",")
		}
		return hasFeature, value, nil

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
		authors := doc.Authors()
		hasAuthors := len(authors) > 0
		value := ""
		if hasAuthors {
			authorNames := make([]string, len(authors))
			for i, author := range authors {
				authorNames[i] = author.GetName()
			}
			value = strings.Join(authorNames, ", ")
		}
		return hasAuthors, value, nil

	case "sbom_with_creator_and_version":
		if len(doc.Tools()) > 0 {
			tool := doc.Tools()[0]
			value := fmt.Sprintf("%s v%s", tool.GetName(), tool.GetVersion())
			return true, value, nil
		}
		return false, "", nil

	case "sbom_with_primary_component":
		if doc.PrimaryComp() != nil {
			return true, doc.PrimaryComp().GetName(), nil
		}
		return false, "", nil

	case "sbom_dependencies":
		if doc.PrimaryComp() != nil {
			count := doc.PrimaryComp().GetTotalNoOfDependencies()
			return count > 0, fmt.Sprintf("%d dependencies", count), nil
		}
		return false, "", nil

	case "sbom_sharable":
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
		hasFeature := len(lics) > 0 && freeLicCount == len(lics)
		value := strings.Join(licenseNames, ",")
		if !hasFeature {
			value = "Not present"
		}
		return hasFeature, value, nil

	case "sbom_parsable":
		return doc.Spec().Parsable(), "SBOM is parsable", nil

	case "sbom_spec":
		return doc.Spec().GetSpecType() != "", doc.Spec().GetSpecType(), nil

	case "sbom_spec_file_format":
		return doc.Spec().FileFormat() != "", doc.Spec().FileFormat(), nil

	case "sbom_spec_version":
		return doc.Spec().GetVersion() != "", doc.Spec().GetVersion(), nil

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
		return "Primary Component"

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
