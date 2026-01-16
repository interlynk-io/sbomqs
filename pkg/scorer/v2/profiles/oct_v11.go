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
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// OCTV11SBOMSpec: SPDX Version / specVersion
func OCTV11SBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing SBOMSpec function - validates both SPDX and CycloneDX
	return SBOMSpec(doc)
}

// OCTV11SBOMSpecVersion: Spec Version
func OCTV11SBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing SBOMSpecVersion function
	return SBOMSpecVersion(doc)
}

// OCTV11SBOMDataLicense: Data License / metadata.licenses
func OCTV11SBOMDataLicense(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		// For SPDX: check data license
		for _, lic := range doc.Spec().GetLicenses() {
			if n := strings.TrimSpace(lic.Name()); n != "" {
				return formulae.ScoreSBOMProfFull("data license", false)
			}
		}
		return formulae.ScoreSBOMProfMissingNA("data license", false)
	}

	// For CycloneDX: check metadata.licenses
	for _, lic := range doc.Spec().GetLicenses() {
		if lic.Name() != "" || lic.ShortID() != "" {
			return formulae.ScoreSBOMProfFull("data license", false)
		}
	}
	return formulae.ScoreSBOMProfMissingNA("data license", false)
}

// OCTV11SBOMIdentifier: SPDX ID / serialNumber
func OCTV11SBOMIdentifier(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		// For SPDX: check SPDXID
		id := strings.TrimSpace(doc.Spec().GetSpdxID())
		if id == "" {
			return formulae.ScoreSBOMProfMissingNA("document identifier", false)
		}
		return formulae.ScoreSBOMProfFull("document identifier", false)
	}

	// For CycloneDX: serialNumber is not directly exposed, use N/A
	// CycloneDX uses serial number but it's not exposed in the interface
	return formulae.ScoreProfNA(false)
}

// OCTV11SBOMName: Document Name (SPDX only)
func OCTV11SBOMName(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	if spec == "cyclonedx" {
		// CycloneDX doesn't have document name - N/A
		return formulae.ScoreProfNA(false)
	}

	// For SPDX: check document name
	name := strings.TrimSpace(doc.Spec().GetName())
	if name == "" {
		return formulae.ScoreSBOMProfMissingNA("document name", false)
	}
	return formulae.ScoreSBOMProfFull("document name", false)
}

// OCTV11SBOMNamespace: Document Namespace (SPDX only)
func OCTV11SBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	if spec == "cyclonedx" {
		// CycloneDX doesn't have namespace - N/A
		return formulae.ScoreProfNA(false)
	}

	// For SPDX: check namespace/URI
	ns := strings.TrimSpace(doc.Spec().GetURI())
	if ns == "" {
		return formulae.ScoreSBOMProfMissingNA("document namespace", false)
	}
	return formulae.ScoreSBOMProfFull("document namespace", false)
}

// OCTV11SBOMCreator: Creator (Organization & Tool)
func OCTV11SBOMCreator(doc sbom.Document) catalog.ProfFeatScore {
	// Check for both organization and tool
	hasOrg := false
	hasTool := false

	// Check organization
	if org := strings.TrimSpace(doc.Spec().GetOrganization()); org != "" {
		hasOrg = true
	}

	// Check authors (for CycloneDX metadata.authors)
	if !hasOrg {
		authors := doc.Authors()
		if len(authors) > 0 {
			for _, author := range authors {
				if author.GetName() != "" {
					hasOrg = true
					break
				}
			}
		}
	}

	// Check tool
	tools := doc.Tools()
	for _, tool := range tools {
		if tool.GetName() != "" {
			hasTool = true
			break
		}
	}

	if hasOrg && hasTool {
		return formulae.ScoreSBOMProfFull("creator info", false)
	}
	return formulae.ScoreSBOMProfMissingNA("creator info", false)
}

// OCTV11SBOMTimestamp: Created timestamp
func OCTV11SBOMTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing SBOMCreationTimestamp function
	return SBOMCreationTimestamp(doc)
}

// OCTV11SBOMCreatorComment: Creator Comment / lifecycles
func OCTV11SBOMCreatorComment(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	if spec == "spdx" {
		// For SPDX: check creator comment
		comment := strings.TrimSpace(doc.Spec().GetComment())
		if comment != "" {
			return formulae.ScoreSBOMProfFull("creator comment", false)
		}
		return formulae.ScoreSBOMProfMissingNA("creator comment", false)
	}

	// For CycloneDX: check lifecycles
	lifecycle := doc.Lifecycles()
	if len(lifecycle) > 0 {
		return formulae.ScoreSBOMProfFull("lifecycle info", false)
	}
	return formulae.ScoreSBOMProfMissingNA("lifecycle info", false)
}

// OCTV11CompName: Package Name
func OCTV11CompName(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing CompName function
	return CompName(doc)
}

// OCTV11CompIdentifier: Package SPDX ID / bom-ref
func OCTV11CompIdentifier(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreSBOMProfMissingNA("component identifier", false)
	}

	spec := doc.Spec().GetSpecType()
	have := 0

	if spec == "spdx" {
		// For SPDX: check SPDXID
		have = lo.CountBy(comps, func(c sbom.GetComponent) bool {
			return strings.TrimSpace(c.GetSpdxID()) != ""
		})
	} else {
		// For CycloneDX: check ID (which maps to bom-ref)
		have = lo.CountBy(comps, func(c sbom.GetComponent) bool {
			return strings.TrimSpace(c.GetID()) != ""
		})
	}

	return formulae.ScoreProfFull(have, len(comps), false)
}

// OCTV11CompVersion: Package Version
func OCTV11CompVersion(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing CompVersion function
	return CompVersion(doc)
}

// OCTV11CompSupplier: Package Supplier
func OCTV11CompSupplier(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing CompSupplier function
	return CompSupplier(doc)
}

// OCTV11CompDownloadLocation: Package Download Location / externalReferences
func OCTV11CompDownloadLocation(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing CompDownloadCodeURL function
	return CompDownloadCodeURL(doc)
}

// OCTV11CompLicenseConcluded: Package License Concluded
func OCTV11CompLicenseConcluded(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing CompConcludedLicenses function
	return CompConcludedLicenses(doc)
}

// OCTV11CompLicenseDeclared: Package License Declared
func OCTV11CompLicenseDeclared(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing CompDeclaredLicenses function
	return CompDeclaredLicenses(doc)
}

// OCTV11CompCopyright: Package Copyright Text
func OCTV11CompCopyright(doc sbom.Document) catalog.ProfFeatScore {
	// Reuse existing CompCopyright function
	return CompCopyright(doc)
}

// OCTV11SBOMRelationships: Relationships (DESCRIBES and CONTAINS)
func OCTV11SBOMRelationships(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMDepedencies(doc)
}

// OCTV11CompChecksum: Package Checksum (SHOULD)
func OCTV11CompChecksum(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return len(c.GetChecksums()) > 0
	})

	return formulae.ScoreProfFull(have, len(comps), true)
}

// OCTV11CompPURL: External Reference PURL (SHOULD)
func OCTV11CompPURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return len(c.GetPurls()) > 0
	})

	return formulae.ScoreProfFull(have, len(comps), true)
}
