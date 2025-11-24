// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	purl "github.com/package-url/packageurl-go"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// isSupplierEntity check whether supplier is a legal entity or not:
// supplier should have either name/email info.
// these info represents a legal entity
func IsSupplierEntity(supplier sbom.GetSupplier) bool {
	if supplier.GetName() != "" || supplier.GetEmail() != "" {
		return true
	}
	return false
}

// isSBOMAuthorEntity check whether author is a legal entity or not:
// author should have name + email/phone info.
func IsSBOMAuthorEntity(doc sbom.Document) bool {
	for _, author := range doc.Authors() {
		if author.GetName() != "" || author.GetEmail() != "" {
			return true
		}
	}
	return false
}

// Checks if component has primary purpose or type
func HasComponentPrimaryPackageType(compType string) bool {
	if strings.TrimSpace(compType) != "" {
		return true
	}
	return false
}

func HasComponentSourceCodeURL(sourceCodeURL string) bool {
	if strings.TrimSpace(sourceCodeURL) != "" {
		return true
	}
	return false
}

func HasSBOMPrimaryComponent(doc sbom.Document) bool {
	return doc.PrimaryComp().IsPresent()
}

func HasComponentDependencies(c sbom.GetComponent) bool {
	return c.HasRelationShips() || c.CountOfDependencies() > 0
}

func IsValidPURL(s string) bool {
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

func IsValidCPE(s string) bool {
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

func CompHasAnyPURLs(c sbom.GetComponent) bool {
	for _, p := range c.GetPurls() {
		if IsValidPURL(string(p)) {
			return true
		}
	}
	return false
}

func CompHasAnyCPEs(c sbom.GetComponent) bool {
	for _, p := range c.GetCpes() {
		if IsValidCPE(string(p)) {
			return true
		}
	}
	return false
}

// license with "NOASSERTION" or "NONE" are considered as
// non-meaningful licenses
func ValidateLicenseText(s string) bool {
	if s == "" {
		return false
	}

	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "NOASSERTION" || u == "NONE" {
		return false
	}
	return true
}

func ValidationCheckConcludedLicenses(c sbom.GetComponent) bool {
	lics := c.ConcludedLicenses()
	if len(lics) == 0 {
		return false
	}

	return AreLicensesValid(lics)
}

func AreLicensesValid(licenses []licenses.License) bool {
	if len(licenses) == 0 {
		return false
	}
	var spdx, aboutcode, custom int

	for _, license := range licenses {
		switch license.Source() {
		case "spdx":
			spdx++
		case "aboutcode":
			aboutcode++
		case "custom":
			if strings.HasPrefix(license.ShortID(), "LicenseRef-") || strings.HasPrefix(license.Name(), "LicenseRef-") {
				custom++
			}
		}
	}

	return spdx+aboutcode+custom == len(licenses)
}

func ComponentHasAnyConcluded(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if id := strings.TrimSpace(l.ShortID()); ValidateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); ValidateLicenseText(nm) {
			return true
		}
	}
	return false
}

func ComponentHasAnyDeclared(c sbom.GetComponent) bool {
	for _, l := range c.DeclaredLicenses() {
		if id := strings.TrimSpace(l.ShortID()); ValidateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); ValidateLicenseText(nm) {
			return true
		}
	}
	return false
}

func ComponentHasAnyDeprecated(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Deprecated() {
			return true
		}
	}
	return false
}

func ComponentHasAnyRestrictive(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Restrictive() {
			return true
		}
	}
	return false
}

func HasSHA1Plus(c sbom.GetComponent) bool {
	for _, checksum := range c.GetChecksums() {
		if isSHA1Plus(checksum.GetAlgo()) && strings.TrimSpace(checksum.GetContent()) != "" {
			return true
		}
	}
	return false
}

func isSHA1Plus(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	switch n {
	case "SHA1", "SHA256", "SHA384", "SHA512":
		return true
	default:
		return false
	}
}

func HasSHA256Plus(c sbom.GetComponent) bool {
	for _, checksum := range c.GetChecksums() {
		if isSHA256Plus(checksum.GetAlgo()) && strings.TrimSpace(checksum.GetContent()) != "" {
			return true
		}
	}
	return false
}

func isSHA256Plus(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	switch n {
	case "SHA256", "SHA384", "SHA512":
		return true
	default:
		return false
	}
}
