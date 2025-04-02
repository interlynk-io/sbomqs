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
)

func ComponentsListResult(ctx context.Context, features []string, doc sbom.Document, path string, missing bool) (*ListResult, error) {
	log := logger.FromContext(ctx)
	log.Debug("list.ComponentsListResult()")

	result := &ListResult{
		FilePath: path,
		Missing:  missing,
	}

	if doc == nil {
		log.Debugf("sbom document is nil\n")
		return result, fmt.Errorf("sbom document is nil")
	}

	// Validate the feature
	if len(features) != 1 {
		log.Debug("exactly one feature must be specified")
		result.Errors = append(result.Errors, "exactly one feature must be specified")
		return result, fmt.Errorf("exactly one feature must be specified")
	}

	feature := features[0]
	result.Feature = feature

	// Determine if the feature is component-based or SBOM-based
	if strings.HasPrefix(feature, "comp_") {
		// Component-based feature
		result.Components = []ComponentResult{}

		// Evaluate the feature for each component
		for _, comp := range doc.Components() {
			hasFeature, err := evaluateComponentFeature(feature, comp)
			if err != nil {
				log.Debugf("failed to evaluate feature %s for component: %v", feature, err)
				result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for component: %v", feature, err))
				continue
			}

			matchesCriteria := (hasFeature && !missing) || (!hasFeature && missing)
			if matchesCriteria {
				result.Components = append(result.Components, ComponentResult{
					Name:    comp.GetName(),
					Version: comp.GetVersion(),
				})
			}
		}
	} else if strings.HasPrefix(feature, "sbom_") {
		// SBOM-based feature
		hasFeature, value, err := evaluateSBOMFeature(feature, doc)
		if err != nil {
			log.Debugf("failed to evaluate feature %s for document: %v", feature, err)
			result.Errors = append(result.Errors, fmt.Sprintf("failed to evaluate feature %s for document: %v", feature, err))
			return result, err
		}

		matchesCriteria := (hasFeature && !missing) || (!hasFeature && missing)
		result.DocumentProperty = DocumentPropertyResult{
			Property: featureToPropertyName(feature),
			Present:  hasFeature,
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

	return result, nil
}

// evaluateComponentFeature evaluates a component-based feature for a single component
func evaluateComponentFeature(feature string, comp sbom.GetComponent) (bool, error) {
	switch feature {
	case "comp_with_name":
		return comp.GetName() != "", nil
	case "comp_with_version":
		return comp.GetVersion() != "", nil
	case "comp_with_supplier":
		return comp.Suppliers().IsPresent(), nil
	case "comp_with_uniq_ids":
		return comp.GetID() != "", nil
	case "comp_valid_licenses":
		// Assuming a method to check if the license is valid (simplified for now)
		licenses := comp.Licenses()
		return len(licenses) > 0 && licenses[0].Name() != "NOASSERTION", nil
	case "comp_with_any_vuln_lookup_id":
		// Simplified: assuming a method to check for vulnerability lookup IDs
		return false, nil // Placeholder
	case "comp_with_deprecated_licenses":
		// Simplified: assuming a method to check for deprecated licenses
		return false, nil // Placeholder
	case "comp_with_multi_vuln_lookup_id":
		// Simplified: assuming a method to check for multiple vulnerability lookup IDs
		return false, nil // Placeholder
	case "comp_with_primary_purpose":
		// Simplified: assuming a method to check for primary purpose
		return false, nil // Placeholder
	case "comp_with_restrictive_licenses":
		// Simplified: assuming a method to check for restrictive licenses
		return false, nil // Placeholder
	case "comp_with_checksums":
		return len(comp.GetChecksums()) > 0, nil
	case "comp_with_licenses":
		return len(comp.Licenses()) > 0, nil
	default:
		return false, fmt.Errorf("unsupported component feature: %s", feature)
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
				authorNames[i] = author.GetName() // Assuming GetName() retrieves the author's name as a string
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
	case "sbom_required_fields":
		// Simplified: assuming required fields are always present if the document is parsed
		return true, "Document fields present", nil
	case "sbom_sharable":
		// Simplified: assuming a method to check for a sharable license
		return false, "", nil // Placeholder
	case "sbom_parsable":
		// Assuming the document is parsable if it was successfully parsed
		return true, "SBOM is parsable", nil
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
