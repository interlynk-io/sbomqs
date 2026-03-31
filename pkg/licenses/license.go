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

// Package licenses provides license validation and handling functionality
// for processing and validating license identifiers in SBOM documents.
package licenses

import (
	"errors"
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

type License interface {
	Name() string
	ShortID() string
	Deprecated() bool
	OsiApproved() bool
	FsfLibre() bool
	FreeAnyUse() bool
	Restrictive() bool
	Exception() bool
	Source() string
	Custom() bool
	Spdx() bool
	AboutCode() bool
}

type meta struct {
	name        string
	short       string
	deprecated  bool
	osiApproved bool
	fsfLibre    bool
	freeAnyUse  bool
	restrictive bool
	exception   bool
	source      string
}

func (m meta) Name() string {
	return m.name
}

func (m meta) ShortID() string {
	return m.short
}

func (m meta) Deprecated() bool {
	return m.deprecated
}

func (m meta) OsiApproved() bool {
	return m.osiApproved
}

func (m meta) FsfLibre() bool {
	return m.fsfLibre
}

func (m meta) FreeAnyUse() bool {
	return m.freeAnyUse
}

func (m meta) Restrictive() bool {
	return m.restrictive
}

func (m meta) Exception() bool {
	return m.exception
}

func (m meta) Source() string {
	return m.source
}

func (m meta) Custom() bool {
	return m.source == "custom"
}

func (m meta) Spdx() bool {
	return m.source == "spdx"
}

func (m meta) AboutCode() bool {
	return m.source == "aboutcode"
}

func LookupSpdxLicense(licenseKey string) (License, error) {
	if licenseKey == "" {
		return nil, errors.New("license not found")
	}

	lowerKey := strings.ToLower(licenseKey)

	if lowerKey == "none" || lowerKey == "noassertion" {
		return nil, errors.New("license not found")
	}

	// Lookup spdx & exception list
	license, ok := licenseList[licenseKey]
	if !ok {
		return nil, errors.New("license not found")
	}

	license = overlayRestrictiveFromAboutCode(license)

	return license, nil
}

func LookupAboutCodeLicense(licenseKey string) (License, error) {
	if licenseKey == "" {
		return nil, errors.New("license not found")
	}

	lowerKey := strings.ToLower(licenseKey)

	if lowerKey == "none" || lowerKey == "noassertion" {
		return nil, errors.New("license not found")
	}

	tLicKey := strings.TrimRight(licenseKey, "+")

	license, ok := licenseListAboutCode[tLicKey]

	if !ok {
		return nil, errors.New("license not found")
	}

	return license, nil
}

func LookupExpression(expression string, customLicenses []License) []License {
	customLookup := func(licenseKey string) (License, error) {
		if len(customLicenses) == 0 {
			return nil, errors.New("license not found")
		}

		for _, l := range customLicenses {
			if l.ShortID() == licenseKey {
				return l, nil
			}
		}
		return nil, errors.New("license not found")
	}

	lExp := strings.ToLower(expression)

	if expression == "" || lExp == "none" || lExp == "noassertion" {
		return []License{}
	}

	var extLicenses []string
	var err error

	// --- IMPORTANT FIX ---
	// SPDX expression parser treats '+' as a grammatical operator.
	// Deprecated SPDX IDs ending with '+' (e.g. LGPL-2.0+) get normalized
	// and lose their original deprecated form.
	if lis, ok := licenseList[expression]; ok &&
		lis.deprecated && strings.HasSuffix(lis.ShortID(), "+") {

		// Preserve deprecated '+' license exactly as authored
		extLicenses = []string{lis.ShortID()}

	} else {
		// Normal path: semantic parsing
		// spdxexp replaces "+" operator
		//
		// Complex license expressions with many AND/OR operators can cause
		// the SPDX expression parser to hang due to exponential parsing
		// complexity (e.g., kernel-headers license strings).
		// Split top-level AND clauses and parse each independently to
		// avoid the pathological behavior.
		extLicenses, err = extractLicensesSafe(expression)
		if err != nil {
			return []License{CreateCustomLicense(expression, expression)}
		}
	}

	licenses := []License{}

	for _, l := range extLicenses {

		license, err := LookupSpdxLicense(l)

		if err == nil {
			licenses = append(licenses, license)
			continue
		}

		license, err = LookupAboutCodeLicense(l)
		if err == nil {
			licenses = append(licenses, license)
			continue
		}

		// if custom license list is provided use that.
		license, err = customLookup(l)
		if err == nil {
			licenses = append(licenses, license)
			continue
		}

		// if nothing else this license is custom
		licenses = append(licenses, CreateCustomLicense(l, l))
	}

	return licenses
}

// maxDirectExtractOperators is the threshold above which we split the
// expression at top-level AND boundaries before feeding sub-expressions
// to spdxexp.ExtractLicenses. The go-spdx parser exhibits exponential
// behaviour on large compound expressions.
const maxDirectExtractOperators = 20

// extractLicensesSafe wraps spdxexp.ExtractLicenses with a guard against
// pathologically complex expressions. When the expression contains more
// than maxDirectExtractOperators boolean operators, it is split at top-level
// AND boundaries and each clause is parsed individually.
func extractLicensesSafe(expression string) ([]string, error) {
	if strings.Count(expression, " AND ")+strings.Count(expression, " OR ") <= maxDirectExtractOperators {
		return spdxexp.ExtractLicenses(expression)
	}

	// Split at top-level AND boundaries (outside parentheses).
	clauses := splitTopLevelAND(expression)

	seen := map[string]bool{}
	var all []string
	for _, clause := range clauses {
		lics, err := spdxexp.ExtractLicenses(strings.TrimSpace(clause))
		if err != nil {
			// Treat unparseable clauses as custom licenses.
			clause = strings.TrimSpace(clause)
			if !seen[clause] {
				all = append(all, clause)
				seen[clause] = true
			}
			continue
		}
		for _, l := range lics {
			if !seen[l] {
				all = append(all, l)
				seen[l] = true
			}
		}
	}
	return all, nil
}

// splitTopLevelAND splits an SPDX expression at top-level " AND " tokens,
// i.e. those not inside parentheses.
func splitTopLevelAND(expr string) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(expr); i++ {
		switch expr[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ' ':
			if depth == 0 && i+5 <= len(expr) && expr[i:i+5] == " AND " {
				parts = append(parts, expr[start:i])
				start = i + 5
				i += 4 // skip past " AND "
			}
		}
	}
	parts = append(parts, expr[start:])
	return parts
}

func CreateCustomLicense(id, name string) License {
	return meta{
		name:        name,
		short:       id,
		deprecated:  false,
		osiApproved: false,
		fsfLibre:    false,
		freeAnyUse:  false,
		restrictive: false,
		exception:   false,
		source:      "custom",
	}
}

// overlayRestrictiveFromAboutCode sets spdx.restrictive to true if AboutCode
// metadata marks the same license ID as restrictive. No other fields are changed.
func overlayRestrictiveFromAboutCode(spdx meta) meta {
	if spdx.restrictive {
		return spdx
	}

	// --NOTE--
	// SPDX itself does not define any “restrictive” flag or field for licenses.
	// We use AboutCode license categories to determine the resctriveness of a license.
	// So, if a category `Copyleft` or `Copyleft Limited` category, then it is
	// considered to be a “restrictive” license.
	if ac, ok := licenseListAboutCode[spdx.short]; ok && ac.restrictive {
		spdx.restrictive = true
	}
	return spdx
}
