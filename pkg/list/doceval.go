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
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/samber/lo"
)

// evaluateSBOMTImestamp evaluates SBOM Timestamp
func evaluateSBOMTImestamp(doc sbom.Document) (bool, string, error) {
	timestamp := doc.Spec().GetCreationTimestamp()
	return timestamp != "", timestamp, nil
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

	if spec == string(sbom.SBOMSpecSPDX) {
		count := lo.Count(validBsiSpdxVersions, specVersion)
		if count == 0 {
			return false, "", fmt.Errorf("SBOM spec version %s is not compliant with BSI SPDX versions", specVersion)
		}
		return true, specVersion, nil
	} else if spec == string(sbom.SBOMSpecCDX) {

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
	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecSPDX) {
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
	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecSPDX) {
		return false, "no-deterministic-field in spdx", nil
	}

	lifecycles := doc.Lifecycles()
	found := lo.Count(lifecycles, "build")
	if found == 0 {
		return false, "no build lifecycle found", nil
	}

	return true, lifecycles[found-1], nil
}

// evaluateSBOMBuildProcess evaluates if the SBOM has a build process
func evaluateSBOMSPDXID(doc sbom.Document) (bool, string, error) {
	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) {
		return false, "no-deterministic-field in spdx", nil
	}

	spdxid := doc.Spec().GetSpdxID()
	if strings.TrimSpace(spdxid) == "" {
		return false, "", nil
	}
	return true, spdxid, nil
}

// evaluateSBOMBuildProcess evaluates if the SBOM has a build process
func evaluateSBOMMachineFormat(doc sbom.Document) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	format := strings.TrimSpace(strings.ToLower(doc.Spec().FileFormat()))

	if spec == "" {
		return false, "", nil
	}

	if format == "" {
		return false, "", nil
	}

	supportedFileFormats := sbom.SupportedSBOMFileFormats(spec)
	for _, f := range supportedFileFormats {
		if format == strings.ToLower(strings.TrimSpace(f)) {
			return true, spec + "-" + format, nil
		}
	}

	return false, "", nil
}

// Creator Organization
func evaluateSBOMOrganization(doc sbom.Document) (bool, string, error) {
	org := strings.TrimSpace(doc.Spec().GetOrganization())
	if org == "" {
		return false, "", nil
	}

	return true, org, nil
}

// schema
func evaluateSBOMSchema(doc sbom.Document) (bool, string, error) {
	if doc.SchemaValidation() {
		return true, "valid schema", nil
	}
	return false, "invalid schema", nil
}

// evaluateSBOMWithBomLinks evaluates if the SBOM has BOM links
func evaluateSBOMWithBomLinks(doc sbom.Document) (bool, string, error) {
	bomLinks := doc.Spec().GetExtDocRef()
	if len(bomLinks) == 0 {
		return false, "", nil
	}

	linkValues := make([]string, 0, len(bomLinks))
	linkValues = append(linkValues, bomLinks...)
	if len(linkValues) == 0 {
		return false, "", nil
	}
	return true, strings.Join(linkValues, ", "), nil
}
