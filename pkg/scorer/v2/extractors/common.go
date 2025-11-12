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

package extractors

import (
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/knqyf263/go-cpe/naming"
	purl "github.com/package-url/packageurl-go"
)

// license with "NOASSERTION" or "NONE" are considered as
// non-meaningful licenses
func validateLicenseText(s string) bool {
	if s == "" {
		return false
	}

	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "NOASSERTION" || u == "NONE" {
		return false
	}
	return true
}

func validationCheckConcludedLicenses(c sbom.GetComponent) bool {
	lics := c.ConcludedLicenses()
	if len(lics) == 0 {
		return false
	}

	return areLicensesValid(lics)
}

func areLicensesValid(licenses []licenses.License) bool {
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

func componentHasAnyConcluded(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if id := strings.TrimSpace(l.ShortID()); validateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); validateLicenseText(nm) {
			return true
		}
	}
	return false
}

func componentHasAnyDeclared(c sbom.GetComponent) bool {
	for _, l := range c.DeclaredLicenses() {
		if id := strings.TrimSpace(l.ShortID()); validateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); validateLicenseText(nm) {
			return true
		}
	}
	return false
}

func componentHasAnyDeprecated(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Deprecated() {
			return true
		}
	}
	return false
}

func componentHasAnyRestrictive(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Restrictive() {
			return true
		}
	}
	return false
}

func compHasAnyPURLs(c sbom.GetComponent) bool {
	for _, p := range c.GetPurls() {
		if isValidPURL(string(p)) {
			return true
		}
	}
	return false
}

func compHasAnyCPEs(c sbom.GetComponent) bool {
	for _, p := range c.GetCpes() {
		if isValidCPE(string(p)) {
			return true
		}
	}
	return false
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
