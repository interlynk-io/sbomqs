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

	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"

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
	case string(sbom.SBOMSpecCDX):
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

	case string(sbom.SBOMSpecSPDX):
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

// BSIV21CompFilename checks that components have a distribution artifact filename declared.
//
// Distribution Artifact Filename Mapping:
// SPDX 2.x: packages[].packageFileName
// SPDX 3.0: software_File.name linked via hasDistributionArtifact relationship
//
//	from software_Package (no embedded filename field).
//
// CDX: components[].properties[] with name="bsi:component:filename"
func BSIV21CompFilename(doc sbom.Document) catalog.ProfFeatScore {
	return componentStringCheck(doc, "filename", func(c sbom.GetComponent) string {
		return c.GetFilename()
	})
}

// BSIV21CompExecutableProperty checks that components have an executable distribution artifact.
func BSIV21CompExecutableProperty(doc sbom.Document) catalog.ProfFeatScore {
	return componentBoolCheck(doc, "executable property", func(c sbom.GetComponent) bool {
		return c.DistributionArtifact().IsExecutable()
	})
}

// BSIV21CompArchiveProperty checks that components have an archive distribution artifact.
func BSIV21CompArchiveProperty(doc sbom.Document) catalog.ProfFeatScore {
	return componentBoolCheck(doc, "archive property", func(c sbom.GetComponent) bool {
		return c.DistributionArtifact().IsArchive()
	})
}

// BSIV21CompStructuredProperty checks that components have a structured distribution artifact.
func BSIV21CompStructuredProperty(doc sbom.Document) catalog.ProfFeatScore {
	return componentBoolCheck(doc, "structured property", func(c sbom.GetComponent) bool {
		return c.DistributionArtifact().IsStructured()
	})
}

// BSIV21CompEffectiveLicence checks that components have effective licenses declared.
// SPDX 3.0: uses hasEffectiveLicense relationship (non-standard but used by BSI v2.1).
// CDX: bsi:component:effectiveLicence property. The BSI property taxonomy spells it
// "effectiveLicence"; TR-03183-2 v2.1.0 (Table 12) spells it "effectiveLicense".
// Both spellings are accepted.
func BSIV21CompEffectiveLicence(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		for _, l := range c.EffectiveLicenses() {
			if isAcceptableLicense(l) {
				return true
			}
		}

		return bsiPropertyValue(c,
			"bsi:component:effectiveLicence",
			"bsi:component:effectiveLicense") != ""
	})

	return componentScore(valid, total, "effective licence")
}

// BSIV21CompDeployableHash checks that components have a hash on their distribution or distribution-intake external reference.
// BSI v2.1 maps this to externalReferences[].hashes[] with type="distribution" or "distribution-intake".
func BSIV21CompDeployableHash(doc sbom.Document) catalog.ProfFeatScore {
	// BSI v2.1 §5.2.2: deployable hash MUST be SHA-512.
	// SPDX 3.0: hash is on the distribution artifact file (software_File.verifiedUsing),
	// not on an external reference. Check both sources.
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		// Check 1: external reference hash (CDX, SPDX 2.x)
		for _, er := range c.ExternalReferences() {
			if er.GetRefType() == "distribution" || er.GetRefType() == "distribution-intake" {
				for _, h := range er.GetRefHashes() {
					if common.NormalizeAlgoName(h.GetAlgo()) == "SHA512" && strings.TrimSpace(h.GetContent()) != "" {
						return true
					}
				}
			}
		}
		// Check 2: distribution artifact hash (SPDX 3.0)
		for _, h := range c.DistributionArtifact().GetHashes() {
			if common.NormalizeAlgoName(h.GetAlgo()) == "SHA512" && strings.TrimSpace(h.GetContent()) != "" {
				return true
			}
		}
		return false
	})

	return componentScore(valid, total, "deployable component hash")
}

// BSIV21CompSourceHash checks that components have a SHA-512 hash on their source-distribution or vcs external reference.
// SPDX 3.0: source code hash from software_SoftwareArtifact.verifiedUsing linked via generates relationship.
// Source hash is an optional field — absence does not penalise the score (Ignore=true when absent).
func BSIV21CompSourceHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found", Ignore: true}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		// CDX: externalReferences[type=source-distribution or vcs].hashes
		for _, er := range c.ExternalReferences() {
			t := er.GetRefType()
			if t == "source-distribution" || t == "vcs" {
				for _, h := range er.GetRefHashes() {
					content := strings.TrimSpace(h.GetContent())
					if content != "" {
						algo := common.NormalizeAlgoName(h.GetAlgo())
						if algo == "SHA512" {
							return true
						}
					}
				}
			}
		}

		// SPDX 3.0: check SourceCodeHash from source artifact verifiedUsing
		hash := strings.TrimSpace(c.SourceCodeHash())
		if hash != "" {
			parts := strings.SplitN(hash, ":", 2)
			if len(parts) == 2 {
				algo := strings.ToUpper(strings.TrimSpace(parts[0]))
				if algo == "SHA512" {
					return true
				}
			}
		}

		return false
	})

	if valid == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   "no components declare source code hash",
			Ignore: true,
		}
	}

	return componentScore(valid, total, "source code hash")
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

// BSIV21CompSecurityTxtURL checks that components have a security.txt URL.
// CDX: externalReferences[type=rfc-9116].
// SPDX 3.0: externalRef.externalRefType="securityOther".
func BSIV21CompSecurityTxtURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		for _, er := range c.ExternalReferences() {
			t := er.GetRefType()
			if (t == "rfc-9116" || strings.EqualFold(t, "securityOther")) && strings.TrimSpace(er.GetRefLocator()) != "" {
				return true
			}
		}
		return false
	})

	return componentScore(valid, total, "security.txt URL")
}

// BSIV21CompDownloadURI checks that components have an externalReference of type distribution or distribution-intake with a URL.
// SPDX 3.0: software_downloadLocation on software_Package, OR File.externalRef.externalRefType="binaryArtifact" on distribution artifact.
func BSIV21CompDownloadURI(doc sbom.Document) catalog.ProfFeatScore {
	return extRefOrFieldURLCheck(doc, "deployable form URI", "GetDownloadLocationURL", "distribution", "distribution-intake")
}

// BSIV21CompSourceCodeURI checks that components have an externalReference of type source-distribution or vcs with a URL.
// SPDX 3.0: software_sourceInfo on software_Package, OR software_SoftwareArtifact.externalRef.externalRefType="SourceArtifact" linked via generates relationship.
func BSIV21CompSourceCodeURI(doc sbom.Document) catalog.ProfFeatScore {
	return extRefOrFieldURLCheck(doc, "source code URI", "GetSourceCodeURL", "source-distribution", "vcs")
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

// bsiPropertyValue returns the first non-empty value among the given property names.
func bsiPropertyValue(c sbom.GetComponent, propertyNames ...string) string {
	for _, name := range propertyNames {
		if value := strings.TrimSpace(c.GetPropertyValue(name)); value != "" {
			return value
		}
	}

	return ""
}

// extRefURLCheck checks that components have an externalReference of one of the given types with a non-empty URL.
func extRefURLCheck(doc sbom.Document, fieldLabel string, refTypes ...string) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		for _, er := range c.ExternalReferences() {
			for _, refType := range refTypes {
				if er.GetRefType() == refType && strings.TrimSpace(er.GetRefLocator()) != "" {
					return true
				}
			}
		}
		return false
	})

	return componentScore(valid, total, fieldLabel)
}

// extRefOrFieldURLCheck checks that components have either:
// 1. An externalReference of one of the given types with a non-empty URL (CDX, SPDX 2.x), OR
// 2. A non-empty value from the specified field getter method (SPDX 3.0 sourceInfo/downloadLocation)
func extRefOrFieldURLCheck(doc sbom.Document, fieldLabel string, fieldGetter string, refTypes ...string) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		// First check external references (CDX, SPDX 2.x style).
		// Iterate refTypes first so priority order is respected regardless of JSON order.
		for _, refType := range refTypes {
			for _, er := range c.ExternalReferences() {
				if er.GetRefType() == refType && strings.TrimSpace(er.GetRefLocator()) != "" {
					return true
				}
			}
		}

		// Then check SPDX 3.0 style fields
		switch fieldGetter {
		case "GetSourceCodeURL":
			if strings.TrimSpace(c.GetSourceCodeURL()) != "" {
				return true
			}
		case "GetDownloadLocationURL":
			if strings.TrimSpace(c.GetDownloadLocationURL()) != "" {
				return true
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

// componentBoolCheck checks that components satisfy a boolean condition.
func componentBoolCheck(doc sbom.Document, fieldLabel string, check func(sbom.GetComponent) bool) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, check)
	return componentScore(valid, total, fieldLabel)
}

// componentStringCheck checks that components have a non-empty string value from a getter.
func componentStringCheck(doc sbom.Document, fieldLabel string, getValue func(sbom.GetComponent) string) catalog.ProfFeatScore {
	comps := doc.Components()
	total := len(comps)

	if total == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no components found"}
	}

	valid := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return strings.TrimSpace(getValue(c)) != ""
	})
	return componentScore(valid, total, fieldLabel)
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
