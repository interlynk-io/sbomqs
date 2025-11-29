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
	commonV2 "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/samber/lo"
)

// evaluate comp with name
func evaluateCompWithName(comp sbom.GetComponent) (bool, string, error) {
	if comp.GetName() != "" {
		return true, comp.GetName(), nil
	}
	return false, "missing", nil
}

// evaluateCompWithVersion evaluates if the component has a version
func evaluateCompWithVersion(comp sbom.GetComponent) (bool, string, error) {
	if comp.GetVersion() != "" {
		return true, comp.GetVersion(), nil
	}
	return false, "missing", nil
}

// evaluateCompWithSupplier evaluates if the component has a supplier
func evaluateCompWithSupplier(comp sbom.GetComponent) (bool, string, error) {
	name := comp.Suppliers().GetName()
	email := comp.Suppliers().GetEmail()

	switch {
	case name != "" && email != "":
		return true, name + ", " + email, nil

	case name != "":
		return true, name, nil

	case email != "":
		return true, email, nil

	default:
		return false, "missing", nil
	}
}

// evaluateCompWithUniqID evaluates if the component has a unique ID
func evaluateCompWithUniqID(comp sbom.GetComponent) (bool, string, error) {
	var allPurls []string
	for _, p := range comp.GetPurls() {
		allPurls = append(allPurls, p.String())
	}

	var allCPEs []string
	for _, c := range comp.GetCpes() {
		allCPEs = append(allCPEs, c.String())
	}

	switch {
	case len(allPurls) > 0 && len(allCPEs) > 0:
		combined := append(allPurls, allCPEs...)
		return true, strings.Join(combined, ", "), nil

	case len(allPurls) > 0:
		return true, strings.Join(allPurls, ", "), nil

	case len(allCPEs) > 0:
		return true, strings.Join(allCPEs, ", "), nil

	default:
		return false, "missing", nil
	}
}

// evaluateCompWithUniqID evaluates if the component has a unique ID
func evaluateCompWithLocalID(comp sbom.GetComponent) (bool, string, error) {
	return comp.GetID() != "", comp.GetID(), nil
}

func evaluateCompWithPURL(comp sbom.GetComponent) (bool, string, error) {
	var all []string
	for _, p := range comp.GetPurls() {
		all = append(all, p.String())
	}

	if len(all) > 0 {
		return true, strings.Join(all, ", "), nil
	}

	return false, "missing", nil
}

func evaluateCompWithCPE(comp sbom.GetComponent) (bool, string, error) {
	var all []string
	for _, c := range comp.GetCpes() {
		all = append(all, c.String())
	}

	if len(all) > 0 {
		return true, strings.Join(all, ", "), nil
	}
	return false, "missing", nil
}

// evaluateCompWithCopyright
func evaluateCompWithCopyright(comp sbom.GetComponent) (bool, string, error) {
	cp := strings.ToLower(strings.TrimSpace(comp.GetCopyRight()))
	if cp != "" {
		return true, cp, nil
	}
	return false, "missing", nil
}

// evaluateCompWithStrongChecksums
func evaluateCompWithStrongChecksums(comp sbom.GetComponent) (bool, string, error) {
	var strong []string
	for _, checksum := range comp.GetChecksums() {
		if commonV2.IsStrongChecksum(normalizeAlgoName(checksum.GetAlgo())) && strings.TrimSpace(checksum.GetContent()) != "" {
			strong = append(strong, checksum.GetAlgo()+": "+checksum.GetContent())
		}
	}
	if len(strong) > 0 {
		return true, strings.Join(strong, ", "), nil
	}

	return false, "missing", nil
}

// evaluateCompWithWeakChecksums
func evaluateCompWithWeakChecksums(comp sbom.GetComponent) (bool, string, error) {
	var weak []string
	for _, checksum := range comp.GetChecksums() {
		if commonV2.IsWeakChecksum(normalizeAlgoName(checksum.GetAlgo())) && strings.TrimSpace(checksum.GetContent()) != "" {
			weak = append(weak, checksum.GetAlgo()+": "+checksum.GetContent())
		}
	}

	if len(weak) > 0 {
		return true, strings.Join(weak, ", "), nil
	}

	return false, "missing", nil
}

func normalizeAlgoName(algo string) string {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)
	return n
}

// evaluateCompWithValidLicenses evaluates if the component has valid licenses
func evaluateCompWithValidLicenses(comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.GetLicenses()
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
		return true, "", nil
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

	if len(allIDs) == 0 {
		return true, "", nil
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
	if len(allIDs) == 0 {
		return true, "", nil
	}

	return hasFeature, strings.Join(allIDs, ","), nil
}

// evaluateCompWithDeprecatedLicenses evaluates if the component has any deprecated licenses
func evaluateCompWithDeprecatedLicenses(comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.GetLicenses()
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
func evaluateCompWithRestrictedLicenses(comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.GetLicenses()
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

	if ok, values := hasAnySHA(comp); ok {
		return true, strings.Join(values, ", "), nil
	}

	return false, "", nil
}

func hasAnySHA(c sbom.GetComponent) (bool, []string) {
	var values []string
	for _, checksum := range c.GetChecksums() {
		if isAnySHA(checksum.GetAlgo()) && strings.TrimSpace(checksum.GetContent()) != "" {
			values = append(values, checksum.GetAlgo())
		}
	}
	if values != nil {
		return true, values
	}

	return false, nil
}

func isAnySHA(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	switch n {
	case "SHA1", "SHA256", "SHA384", "SHA512", "MD5":
		return true
	default:
		return false
	}
}

// evaluateCompWithChecksums evaluates if the component has checksums
func evaluateCompWithChecksums256(comp sbom.GetComponent) (bool, string, error) {
	checksums := comp.GetChecksums()
	if len(checksums) == 0 {
		return false, "", nil
	}

	ok, value := hasSHA256SHA(comp)
	if ok {
		return true, value, nil
	}
	return true, "", nil
}

func hasSHA256SHA(c sbom.GetComponent) (bool, string) {
	for _, checksum := range c.GetChecksums() {
		if isSHA256(checksum.GetAlgo()) && strings.TrimSpace(checksum.GetContent()) != "" {
			return true, checksum.GetAlgo()
		}
	}
	return false, ""
}

func isSHA256(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	if n == "SHA256" {
		return true
	}
	return false
}

// evaluateCompWithLicenses
func evaluateCompWithLicenses(comp sbom.GetComponent) (bool, string, error) {
	licenses := comp.GetLicenses()
	if len(licenses) == 0 {
		return false, "missing", nil
	}

	licenseNames := make([]string, 0, len(licenses))
	licenseIDs := make([]string, 0, len(licenses))
	for _, l := range licenses {
		if l != nil {
			licenseNames = append(licenseNames, l.Name())
			licenseIDs = append(licenseIDs, l.ShortID())
		}
	}

	switch {

	case len(licenseNames) > 0 && len(licenseIDs) > 0:
		combined := append(licenseNames, licenseIDs...)
		return true, strings.Join(combined, ", "), nil

	case len(licenseNames) > 0:
		return true, strings.Join(licenseNames, ", "), nil

	case len(licenseIDs) > 0:
		return true, strings.Join(licenseIDs, ", "), nil

	default:
		return false, "missing", nil
	}
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
		return true, "", nil
	}
	return true, strings.Join(sha256Checksums, ","), nil
}

// evaluateCompWithSourceCodeURI evaluates if the component has a source code URI
func evaluateCompWithSourceCodeURI(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	if doc.Spec().GetSpecType() == "spdx" {
		return false, "source code URI is not supported for SPDX documents", nil
	}

	sourceCodeURI := comp.GetSourceCodeURL()
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

	if spec == string(sbom.SBOMSpecSPDX) {
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
	} else if spec == string(sbom.SBOMSpecCDX) {
		var associatedLicense []string

		for _, l := range comp.GetLicenses() {
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
func evaluateCompWithConcludedLicense(comp sbom.GetComponent) (bool, string, error) {
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
func evaluateCompWithDeclaredLicense(comp sbom.GetComponent) (bool, string, error) {
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
func evaluateCompWithDependencies(comp sbom.GetComponent) (bool, string, error) {
	if comp == nil {
		return false, "", fmt.Errorf("component is nil")
	}

	dependencies := comp.HasRelationShips()
	if !dependencies {
		return false, "no-dependencies", nil
	}

	return true, "contains dependencies", nil
}
