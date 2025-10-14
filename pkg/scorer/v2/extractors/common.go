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
