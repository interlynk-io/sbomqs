package licenses

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

var (
	//go:embed files
	res embed.FS

	licenses = map[string]string{
		"spdx":          "files/licenses_spdx.json",
		"spdxException": "files/licenses_spdx_exception.json",
		"aboutcode":     "files/licenses_aboutcode.json",
	}
)

type spdxLicense struct {
	Version    string              `json:"licenseListVersion"`
	Licenses   []spdxLicenseDetail `json:"licenses"`
	Exceptions []spdxLicenseDetail `json:"exceptions"`
}

type spdxLicenseDetail struct {
	Reference          string   `json:"reference"`
	IsDeprecated       bool     `json:"isDeprecatedLicenseId"`
	DetailsURL         string   `json:"detailsUrl"`
	ReferenceNumber    int      `json:"referenceNumber"`
	Name               string   `json:"name"`
	LicenseID          string   `json:"licenseId"`
	LicenseExceptionID string   `json:"licenseExceptionId"`
	SeeAlso            []string `json:"seeAlso"`
	IsOsiApproved      bool     `json:"isOsiApproved"`
	IsFsfLibre         bool     `json:"isFsfLibre"`
}

type aboutCodeLicenseDetail struct {
	LicenseKey           string   `json:"license_key"`
	Category             string   `json:"category"`
	SpdxLicenseKey       string   `json:"spdx_license_key"`
	OtherSpdxLicenseKeys []string `json:"other_spdx_license_keys"`
	Exception            bool     `json:"is_exception"`
	Deprecated           bool     `json:"is_deprecated"`
	JSON                 string   `json:"json"`
	Yaml                 string   `json:"yaml"`
	HTML                 string   `json:"html"`
	License              string   `json:"license"`
}

var (
	licenseList          = map[string]meta{}
	LicenseListAboutCode = map[string]meta{}
)

func loadSpdxLicense() error {
	licData, err := res.ReadFile(licenses["spdx"])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	var sl spdxLicense
	if err := json.Unmarshal(licData, &sl); err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	for _, l := range sl.Licenses {
		licenseList[l.LicenseID] = meta{
			name:        l.Name,
			short:       l.LicenseID,
			deprecated:  l.IsDeprecated,
			osiApproved: l.IsOsiApproved,
			fsfLibre:    l.IsFsfLibre,
			restrictive: false,
			exception:   false,
			freeAnyUse:  false,
			source:      "spdx",
		}
	}
	// fmt.Printf("loaded %d licenses\n", len(licenseList))
	return nil
}

func loadSpdxExceptions() error {
	licData, err := res.ReadFile(licenses["spdxException"])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	var sl spdxLicense
	if err := json.Unmarshal(licData, &sl); err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	for _, l := range sl.Exceptions {
		licenseList[l.LicenseExceptionID] = meta{
			name:        l.Name,
			short:       l.LicenseExceptionID,
			deprecated:  l.IsDeprecated,
			osiApproved: l.IsOsiApproved,
			fsfLibre:    l.IsFsfLibre,
			restrictive: false,
			exception:   true,
			freeAnyUse:  false,
			source:      "spdx",
		}
	}
	// fmt.Printf("loaded %d licenses\n", len(licenseList))

	return nil
}

func loadAboutCodeLicense() error {
	licData, err := res.ReadFile(licenses["aboutcode"])
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	var acl []aboutCodeLicenseDetail

	if err := json.Unmarshal(licData, &acl); err != nil {
		fmt.Printf("error: %v\n", err)
		return err
	}

	isRestrictive := func(category string) bool {
		lowerCategory := strings.ToLower(category)

		if strings.Contains(lowerCategory, "copyleft") {
			return true
		}

		if strings.Contains(lowerCategory, "restricted") {
			return true
		}

		return false
	}

	isFreeAnyUse := func(category string) bool {
		lowerCategory := strings.ToLower(category)
		return strings.Contains(lowerCategory, "public")
	}

	for _, l := range acl {
		for _, otherKey := range l.OtherSpdxLicenseKeys {
			LicenseListAboutCode[otherKey] = meta{
				name:        l.LicenseKey,
				short:       otherKey,
				deprecated:  l.Deprecated,
				osiApproved: false,
				fsfLibre:    false,
				restrictive: isRestrictive(l.Category),
				exception:   l.Exception,
				freeAnyUse:  isFreeAnyUse(l.Category),
				source:      "aboutcode",
			}
		}

		LicenseListAboutCode[l.SpdxLicenseKey] = meta{
			name:        l.LicenseKey,
			short:       l.SpdxLicenseKey,
			deprecated:  l.Deprecated,
			osiApproved: false,
			fsfLibre:    false,
			restrictive: isRestrictive(l.Category),
			exception:   l.Exception,
			freeAnyUse:  isFreeAnyUse(l.Category),
			source:      "aboutcode",
		}
	}
	// fmt.Printf("loaded %d licenses\n", len(LicenseListAboutCode))

	return nil
}

func init() {
	err := loadSpdxLicense()
	if err != nil {
		log.Printf("Failed to load spdx license: %v", err)
	}
	err = loadSpdxExceptions()
	if err != nil {
		log.Printf("Failed to load spdx exceptions: %v", err)
	}
	err = loadAboutCodeLicense()
	if err != nil {
		log.Printf("Failed to load about code license: %v", err)
	}
}
