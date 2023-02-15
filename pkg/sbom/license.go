// Copyright 2023 Interlynk.io
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

package sbom

import (
	"sort"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/licenses"
)

//counterfeiter:generate . License
type License interface {
	Short() string
	Name() string
	Deprecated() bool
	ValidSpdxLicense() bool
}

type license struct {
	name       string
	short      string
	deprecated bool
}

func (l license) Short() string {
	return l.short
}

func (l license) Name() string {
	return l.name
}

func (l license) Deprecated() bool {
	return l.deprecated
}

func (l license) ValidSpdxLicense() bool {
	return l.name != ""

}
func newLicenseFromID(lic string) []license {
	// The incoming license string could be a
	// - A SPDX short license ID
	// - A SPDX license expression
	// - A proprietary license id

	//NONE and NOASSERTION should be treated as
	// no license
	lcs := []license{}

	licenseLower := strings.ToLower(lic)

	if licenseLower == "none" || licenseLower == "noassertion" {
		return lcs
	}

	allLicenses := getIndividualLicenses(licenseLower)

	for _, l := range allLicenses {
		meta, present := licenses.LookUp(l)
		fl := &license{}
		if present {
			fl.name = meta.Name()
			fl.deprecated = meta.Deprecated()
			fl.short = meta.ShortID()
		}
		fl.short = l
		lcs = append(lcs, *fl)
	}
	return lcs
}

// taken from https://github.com/spdx/tools-golang/blob/main/idsearcher/idsearcher.go#L208
func getIndividualLicenses(lic string) []string {
	// replace parens and '+' with spaces
	lic = strings.Replace(lic, "(", " ", -1)
	lic = strings.Replace(lic, ")", " ", -1)
	lic = strings.Replace(lic, "+", " ", -1)
	lic = strings.Replace(lic, ",", " ", -1) //changed from original

	// now, split by spaces, trim, and add to slice
	licElements := strings.Split(lic, " ")
	lics := []string{}
	for _, elt := range licElements {
		elt := strings.TrimSpace(elt)
		// don't add if empty or if case-insensitive operator
		if elt == "" || strings.EqualFold(elt, "AND") ||
			strings.EqualFold(elt, "OR") || strings.EqualFold(elt, "WITH") {
			continue
		}

		lics = append(lics, elt)
	}

	// sort before returning
	sort.Strings(lics)
	return lics
}
