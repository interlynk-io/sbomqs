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
		return false, "missing", nil
	}

	var all []string

	for _, author := range authors {
		hasName := author.GetName()
		hasEmail := author.GetEmail()

		switch {
		case hasName != "" && hasEmail != "":
			all = append(all, hasName+", "+hasEmail)

		case hasName != "":
			all = append(all, hasName)

		case hasEmail != "":
			all = append(all, hasEmail)

		default:
			return false, "", nil
		}
	}

	if len(all) > 0 {
		return true, strings.Join(all, ", "), nil
	}

	return false, "missing", nil
}

// evaluateSBOMAuthors evaluates if the SBOM has authors
func evaluateSBOMSupplier(doc sbom.Document) (bool, string, error) {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		return false, "no-deterministic-field in spdx", nil

	case string(sbom.SBOMSpecCDX):
		s := doc.Supplier()

		if s != nil {
			hasName := strings.TrimSpace(s.GetName())
			hasEmail := strings.TrimSpace(s.GetEmail())

			switch {
			case hasName != "" && hasEmail != "":
				return true, hasName + ", " + hasEmail, nil

			case hasName != "":
				return true, hasName, nil

			case hasEmail != "":
				return true, hasEmail, nil

			default:
				return false, "mising", nil
			}

		}
	}
	return false, "missing", nil
}

// evaluateSBOMWithCreatorAndVersion evaluates if the SBOM has a creator and version
func evaluateSBOMWithCreatorAndVersion(doc sbom.Document) (bool, string, error) {
	tools := doc.Tools()
	if len(tools) == 0 {
		return false, "missing", nil
	}

	var value []string

	for _, t := range tools {
		name := strings.TrimSpace(t.GetName())
		ver := strings.TrimSpace(t.GetVersion())

		switch {
		case name != "" && ver != "":
			value = append(value, name+":"+ver)
		case name == "" && ver != "":
			value = append(value, name)
		case name != "" && ver == "":
			value = append(value, ver)
		}
	}

	if len(value) > 0 {
		return true, strings.Join(value, ", "), nil
	}

	return false, "missing", nil
}

// evaluateSBOMPrimaryComponent evaluates if the SBOM has a primary component
func evaluateSBOMPrimaryComponent(doc sbom.Document) (bool, string, error) {
	if doc.PrimaryComp().IsPresent() {
		value := fmt.Sprintf("%s v%s", doc.PrimaryComp().GetName(), doc.PrimaryComp().GetVersion())
		return true, value, nil
	}

	return false, "missing", nil
}

// evaluateSBOMDependencies evaluates if the SBOM has dependencies
func evaluateSBOMDependencies(doc sbom.Document) (bool, string, error) {
	var have int
	var all []string

	if doc.PrimaryComp() != nil {
		have = doc.PrimaryComp().GetTotalNoOfDependencies()
		all = append(all, doc.PrimaryComp().GetDependencies()...)
	}

	if have > 0 {
		return true, strings.Join(all, ", "), nil
	}

	return false, "missing", nil
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
	return false, "missing", nil
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
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == "" {
		return false, "missing", nil
	}

	return true, spec, nil
}

// evaluateSBOMSpecVersion evaluates if the SBOM has a specification version
func evaluateSBOMSpecVersion(doc sbom.Document) (bool, string, error) {
	version := doc.Spec().GetVersion()
	if version != "" {
		return true, version, nil
	}
	return false, "missing", nil
}

// evaluateSBOMSpecVersionCompliant evaluates if the SBOM specification version is compliant
func evaluateSBOMSpecVersionCompliant(doc sbom.Document) (bool, string, error) {
	specVersion := doc.Spec().GetVersion()
	spec := doc.Spec().GetSpecType()

	if spec == string(sbom.SBOMSpecSPDX) {
		count := lo.Count(validBsiSpdxVersions, specVersion)
		if count == 0 {
			return false, "missing", fmt.Errorf("SBOM spec version %s is not compliant with BSI SPDX versions", specVersion)
		}
		return true, specVersion, nil
	} else if spec == string(sbom.SBOMSpecCDX) {

		count := lo.Count(validBsiCycloneDXVersions, specVersion)
		if count == 0 {
			return false, "missing", fmt.Errorf("SBOM spec version %s is not compliant with CycloneDX versions", specVersion)
		}
		return true, specVersion, nil
	}

	return false, "missing", nil
}

// evaluateSBOMWithURI evaluates if the SBOM has a URI
func evaluateSBOMWithURI(doc sbom.Document) (bool, string, error) {
	uri := doc.Spec().GetURI()
	if uri != "" {
		return true, uri, nil
	}
	return false, "missing", nil
}

// evaluateSBOMWithVulnerability evaluates if the SBOM has any vulnerabilities
func evaluateSBOMWithVulnerability(doc sbom.Document) (bool, string, error) {
	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecSPDX) {
		return false, "no-deterministic-field in spdx", nil
	}

	vulns := doc.Vulnerabilities()

	if len(vulns) == 0 {
		return false, "missing", nil
	}

	var allVulnIDs []string
	for _, v := range vulns {
		if vulnID := v.GetID(); vulnID != "" {
			allVulnIDs = append(allVulnIDs, vulnID)
		}
	}

	return true, strings.Join(allVulnIDs, ", "), nil
}

// evaluateSBOMBuildProcess evaluates if the SBOM has a build process
func evaluateSBOMBuildLifeCycle(doc sbom.Document) (bool, string, error) {
	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecSPDX) {
		return false, "no-deterministic-field in spdx", nil
	}

	phase := doc.Lifecycles()
	if len(phase) == 0 {
		return false, "missing", nil
	}

	return true, strings.Join(phase, ", "), nil
}

// evaluateSBOMBuildProcess evaluates if the SBOM has a build process
func evaluateSBOMCompleteness(doc sbom.Document) (bool, string, error) {
	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecSPDX) {
		return false, "no-deterministic-field in spdx", nil
	}

	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		return false, "no-deterministic-field in spdx", nil

	case string(sbom.SBOMSpecCDX):
		return true, "deterministic-field in cdx", nil

	default:
		return false, "missing", nil
	}
}

// evaluateSBOMSPDXID evaluates if the SBOM has a build process
func evaluateSBOMSPDXID(doc sbom.Document) (bool, string, error) {
	if doc.Spec().GetSpecType() == string(sbom.SBOMSpecCDX) {
		return false, "no-deterministic-field in cdx", nil
	}

	spdxid := doc.Spec().GetSpdxID()
	if strings.TrimSpace(spdxid) == "" {
		return false, "missing", nil
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

	return false, "missing", nil
}

// Creator Organization
func evaluateSBOMOrganization(doc sbom.Document) (bool, string, error) {
	org := strings.TrimSpace(doc.Spec().GetOrganization())
	if org == "" {
		return false, "missing", nil
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

// schema
func evaluateSBOMLicense(doc sbom.Document) (bool, string, error) {
	specLicenses := doc.Spec().GetLicenses()
	if len(specLicenses) == 0 {
		return false, "missing", nil
	}

	var all []string
	for _, license := range specLicenses {
		all = append(all, license.Name())
	}

	if len(all) > 0 {
		return true, strings.Join(all, ", "), nil
	}

	return false, "missing", nil
}

// evaluateSBOMComment
func evaluateSBOMComment(doc sbom.Document) (bool, string, error) {
	comment := doc.Spec().GetComment()
	if comment != "" {
		return true, comment, nil
	}

	return false, "missing", nil
}

// evaluateSBOMWithBomLinks evaluates if the SBOM has BOM links
func evaluateSBOMWithBomLinks(doc sbom.Document) (bool, string, error) {
	bomLinks := doc.Spec().GetExtDocRef()
	if len(bomLinks) == 0 {
		return false, "missing", nil
	}

	linkValues := make([]string, 0, len(bomLinks))
	linkValues = append(linkValues, bomLinks...)

	if len(linkValues) == 0 {
		return false, "missing", nil
	}
	return true, strings.Join(linkValues, ", "), nil
}
