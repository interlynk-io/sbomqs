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
	"github.com/knqyf263/go-cpe/naming"
	purl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"
)

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
	if !comp.Suppliers().IsPresent() {
		return false, "", nil
	}
	return comp.Suppliers().IsPresent(), comp.Suppliers().GetName() + "," + comp.Suppliers().GetEmail(), nil
}

// evaluateCompWithUniqID evaluates if the component has a unique ID
func evaluateCompWithUniqID(comp sbom.GetComponent) (bool, string, error) {
	return comp.GetID() != "", comp.GetID(), nil
}

func evaluateCompWithPURL(comp sbom.GetComponent) (bool, string, error) {
	have := compHasAnyPURLs(comp)
	if have {
		return true, "contains purls", nil
	}

	return false, "missing purls", nil
}

func evaluateCompWithCPE(comp sbom.GetComponent) (bool, string, error) {
	have := compHasAnyCPEs(comp)
	if have {
		return true, "contains cpes", nil
	}

	return false, "missing cpes", nil
}

func compHasAnyPURLs(c sbom.GetComponent) bool {
	for _, p := range c.GetPurls() {
		if isValidPURL(string(p)) {
			return true
		}
	}
	return false
}

func isValidCPE(s string) bool {
	ls := strings.TrimSpace(s)
	low := strings.ToLower(ls)

	switch {
	case strings.HasPrefix(low, "cpe:2.3:"):
		_, err := naming.UnbindFS(ls)
		return err == nil
	case strings.HasPrefix(low, "cpe:/"):
		_, err := naming.UnbindURI(ls)
		return err == nil
	default:
		return false
	}
}

func isValidPURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	u, err := purl.FromString(s)
	if err != nil {
		return false
	}

	// type and name must be present per spec
	if strings.TrimSpace(u.Type) == "" || strings.TrimSpace(u.Name) == "" {
		return false
	}
	return true
}

func compHasAnyCPEs(c sbom.GetComponent) bool {
	for _, p := range c.GetCpes() {
		if isValidCPE(string(p)) {
			return true
		}
	}
	return false
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
		return false, "", nil
	}

	licenseNames := make([]string, 0, len(licenses))
	for _, l := range licenses {
		if l != nil {
			licenseNames = append(licenseNames, l.Name())
		}
	}
	if len(licenseNames) == 0 {
		return true, "", nil
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
