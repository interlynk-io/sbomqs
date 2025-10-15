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

	tLicKey := strings.TrimRight(licenseKey, "+")

	// Lookup spdx & exception list
	license, ok := licenseList[tLicKey]

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

	extLicenses, err := spdxexp.ExtractLicenses(expression)
	if err != nil {
		return []License{CreateCustomLicense(expression, expression)}
	}

	licenses := []License{}

	for _, l := range extLicenses {
		trimLicenseKey := strings.TrimRight(l, "+")

		license, err := LookupSpdxLicense(trimLicenseKey)
		if err == nil {
			licenses = append(licenses, license)
			continue
		}

		license, err = LookupAboutCodeLicense(trimLicenseKey)
		if err == nil {
			licenses = append(licenses, license)
			continue
		}

		// if custom license list is provided use that.
		license, err = customLookup(trimLicenseKey)
		if err == nil {
			licenses = append(licenses, license)
			continue
		}

		// if nothing else this license is custom
		licenses = append(licenses, CreateCustomLicense(trimLicenseKey, trimLicenseKey))
	}

	return licenses
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
	if ac, ok := licenseListAboutCode[spdx.short]; ok && ac.restrictive {
		spdx.restrictive = true
	}
	return spdx
}
