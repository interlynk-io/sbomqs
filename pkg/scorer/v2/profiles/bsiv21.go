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

package profiles

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/samber/lo"
)

// BSIV21SpecVersion checks that the SBOM format meets BSI v2.1 minimum version requirements.
// CycloneDX >= 1.6, SPDX >= 3.0.1. SPDX v2 is not allowed.
func BSIV21SpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == "" || ver == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM spec type or version is missing",
		}
	}

	switch spec {
	case "cyclonedx":
		if isVersionAtLeast(ver, "1.6") {
			return catalog.ProfFeatScore{
				Score: 10.0,
				Desc:  fmt.Sprintf("CycloneDX %s meets minimum version 1.6", ver),
			}
		}
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  fmt.Sprintf("CycloneDX %s does not meet minimum version 1.6", ver),
		}

	case "spdx":
		if isVersionAtLeast(ver, "3.0") {
			return catalog.ProfFeatScore{
				Score: 10.0,
				Desc:  fmt.Sprintf("SPDX %s meets minimum version 3.0.1", ver),
			}
		}
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  fmt.Sprintf("SPDX %s does not meet minimum version 3.0.1; SPDX v2 is not allowed by BSI v2.1", ver),
		}
	}

	return catalog.ProfFeatScore{
		Score: 0.0,
		Desc:  fmt.Sprintf("unsupported spec type: %s", spec),
	}
}

// BSIV21CompFilename checks that components have the bsi:component:filename property set.
func BSIV21CompFilename(doc sbom.Document) catalog.ProfFeatScore {
	return bsiPropertyCheck(doc, "bsi:component:filename", "filename")
}

// BSIV21CompExecutableProperty checks that components have the bsi:component:executable property set.
func BSIV21CompExecutableProperty(doc sbom.Document) catalog.ProfFeatScore {
	return bsiPropertyCheck(doc, "bsi:component:executable", "executable property")
}

// BSIV21CompArchiveProperty checks that components have the bsi:component:archive property set.
func BSIV21CompArchiveProperty(doc sbom.Document) catalog.ProfFeatScore {
	return bsiPropertyCheck(doc, "bsi:component:archive", "archive property")
}

// BSIV21CompStructuredProperty checks that components have the bsi:component:structured property set.
func BSIV21CompStructuredProperty(doc sbom.Document) catalog.ProfFeatScore {
	return bsiPropertyCheck(doc, "bsi:component:structured", "structured property")
}

// BSIV21CompEffectiveLicence checks that components have the bsi:component:effectiveLicense property set.
func BSIV21CompEffectiveLicence(doc sbom.Document) catalog.ProfFeatScore {
	return bsiPropertyCheck(doc, "bsi:component:effectiveLicense", "effective licence")
}

// BSIV21CompDeployableHash checks that components have a hash on their distribution external reference.
// BSI v2.1 maps this to externalReferences[].hashes[] with type="distribution".
func BSIV21CompDeployableHash(doc sbom.Document) catalog.ProfFeatScore {
	return extRefHashCheck(doc, "distribution", "deployable component hash")
}

// BSIV21CompSourceHash checks that components have a hash on their source-distribution external reference.
func BSIV21CompSourceHash(doc sbom.Document) catalog.ProfFeatScore {
	return extRefHashCheck(doc, "source-distribution", "source code hash")
}

// BSIV21CompDistributionLicence checks that components have concluded licences
// (distribution licences per BSI v2.1: acknowledgement="concluded").
func BSIV21CompDistributionLicence(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		for _, l := range c.ConcludedLicenses() {
			if isAcceptableLicense(l) {
				return true
			}
		}
		return false
	})

	return componentScore(valid, total, "distribution licence (concluded)")
}

// BSIV21CompOriginalLicences checks that components have declared licences
// (original licences per BSI v2.1: acknowledgement="declared").
func BSIV21CompOriginalLicences(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		for _, l := range c.DeclaredLicenses() {
			if isAcceptableLicense(l) {
				return true
			}
		}
		return false
	})

	return componentScore(valid, total, "original licence (declared)")
}

// BSIV21CompOtherIdentifiers checks that components have CPE, SWID, or PURL identifiers.
func BSIV21CompOtherIdentifiers(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		if len(c.GetPurls()) > 0 {
			return true
		}
		if len(c.GetCpes()) > 0 {
			return true
		}
		if len(c.Swids()) > 0 {
			return true
		}
		return false
	})

	return componentScore(valid, total, "unique identifiers (CPE/SWID/purl)")
}

// BSIV21CompSecurityTxtURL checks that components have an externalReference of type rfc-9116.
func BSIV21CompSecurityTxtURL(doc sbom.Document) catalog.ProfFeatScore {
	return extRefURLCheck(doc, "rfc-9116", "security.txt URL")
}

// BSIV21CompDownloadURI checks that components have an externalReference of type distribution with a URL.
func BSIV21CompDownloadURI(doc sbom.Document) catalog.ProfFeatScore {
	return extRefURLCheck(doc, "distribution", "deployable form URI")
}

// BSIV21CompSourceCodeURI checks that components have an externalReference of type source-distribution with a URL.
func BSIV21CompSourceCodeURI(doc sbom.Document) catalog.ProfFeatScore {
	return extRefURLCheck(doc, "source-distribution", "source code URI")
}

// BSIV21SBOMURI checks the SBOM-URI field (serialNumber for CDX, namespace for SPDX).
// In BSI v2.1 this is a SHALL (required) field.
func BSIV21SBOMURI(doc sbom.Document) catalog.ProfFeatScore {
	uri := strings.TrimSpace(doc.Spec().GetURI())
	ns := strings.TrimSpace(doc.Spec().GetNamespace())

	candidate := uri
	if candidate == "" {
		candidate = ns
	}

	if candidate == "" {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM-URI is missing",
		}
	}

	if !isValidURL(candidate) && !strings.HasPrefix(candidate, "urn:") {
		return catalog.ProfFeatScore{
			Score: 0.0,
			Desc:  "SBOM-URI is present but invalid",
		}
	}

	return catalog.ProfFeatScore{
		Score: 10.0,
		Desc:  "SBOM-URI is declared",
	}
}

// --- Helpers ---

// bsiPropertyCheck is a generic checker for BSI component properties (bsi:component:*).
func bsiPropertyCheck(doc sbom.Document, propertyName, fieldLabel string) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetPropertyValue(propertyName)) != ""
	})

	return componentScore(valid, total, fieldLabel)
}

// extRefURLCheck checks that components have an externalReference of a given type with a non-empty URL.
func extRefURLCheck(doc sbom.Document, refType, fieldLabel string) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		for _, er := range c.ExternalReferences() {
			if er.GetRefType() == refType && strings.TrimSpace(er.GetRefLocator()) != "" {
				return true
			}
		}
		return false
	})

	return componentScore(valid, total, fieldLabel)
}

// extRefHashCheck checks that components have an externalReference of a given type with at least one hash.
func extRefHashCheck(doc sbom.Document, refType, fieldLabel string) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		for _, er := range c.ExternalReferences() {
			if er.GetRefType() == refType {
				for _, h := range er.GetRefHashes() {
					if strings.TrimSpace(h.GetContent()) != "" {
						return true
					}
				}
			}
		}
		return false
	})

	return componentScore(valid, total, fieldLabel)
}

// componentScore returns a standard proportional score for component-level checks.
func componentScore(valid, total int, fieldLabel string) catalog.ProfFeatScore {
	if valid == total {
		return catalog.ProfFeatScore{
			Score: 10.0,
			Desc:  fmt.Sprintf("%s declared for all components", fieldLabel),
		}
	}

	if valid > 0 {
		return catalog.ProfFeatScore{
			Score: float64(valid) / float64(total) * 10.0,
			Desc:  fmt.Sprintf("%d/%d components declare %s", valid, total, fieldLabel),
		}
	}

	return catalog.ProfFeatScore{
		Score: 0.0,
		Desc:  fmt.Sprintf("no components declare %s", fieldLabel),
	}
}

// isVersionAtLeast compares two version strings (e.g., "1.6" >= "1.6").
func isVersionAtLeast(version, minVersion string) bool {
	parseParts := func(v string) (int, int) {
		parts := strings.Split(v, ".")
		major, minor := 0, 0
		if len(parts) >= 1 {
			fmt.Sscanf(parts[0], "%d", &major)
		}
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &minor)
		}
		return major, minor
	}

	vMajor, vMinor := parseParts(version)
	mMajor, mMinor := parseParts(minVersion)

	if vMajor > mMajor {
		return true
	}
	return vMajor == mMajor && vMinor >= mMinor
}
