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
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
)

// NTIA2025 Tool Name - New requirement for NTIA 2025
func NTIA2025ToolName(doc sbom.Document) catalog.ProfFeatScore {
	score := 0.0
	desc := "add tool name"

	if tools := doc.Tools(); tools != nil && len(tools) > 0 {
		for _, tool := range tools {
			if name := tool.GetName(); name != "" {
				score = 10.0
				desc = "complete"
				break
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  score,
		Desc:   desc,
		Ignore: false,
	}
}

// NTIA2025 Generation Context - New requirement for NTIA 2025
func NTIA2025GenerationContext(doc sbom.Document) catalog.ProfFeatScore {
	score := 0.0
	desc := "add generation context"
	spec := doc.Spec().GetSpecType()

	if spec == string(sbom.SBOMSpecCDX) {
		// For CycloneDX, check for lifecycles or metadata
		if doc.Spec().GetCreationTimestamp() != "" {
			score = 10.0
			desc = "complete"
		}
	} else if spec == string(sbom.SBOMSpecSPDX) {
		// For SPDX, check if creation timestamp is present as it indicates generation context
		if timestamp := doc.Spec().GetCreationTimestamp(); timestamp != "" {
			score = 10.0
			desc = "complete"
		}
	}

	return catalog.ProfFeatScore{
		Score:  score,
		Desc:   desc,
		Ignore: false,
	}
}

// NTIA2025 Software Producer - Required field for NTIA 2025
func NTIA2025SoftwareProducer(doc sbom.Document) catalog.ProfFeatScore {
	score := 0.0
	desc := "add software producer"

	// Check for supplier
	if supplier := doc.Supplier(); supplier != nil {
		if email := supplier.GetEmail(); email != "" {
			score = 10.0
			desc = "complete"
		} else if url := supplier.GetURL(); url != "" {
			score = 10.0
			desc = "complete"
		} else if name := supplier.GetName(); name != "" {
			score = 10.0
			desc = "complete"
		}
	}

	// If no supplier, check for manufacturer (CycloneDX)
	if score == 0.0 {
		if manufacturer := doc.Manufacturer(); manufacturer != nil {
			if email := manufacturer.GetEmail(); email != "" {
				score = 10.0
				desc = "complete"
			} else if url := manufacturer.GetURL(); url != "" {
				score = 10.0
				desc = "complete"
			} else if name := manufacturer.GetName(); name != "" {
				score = 10.0
				desc = "complete"
			}
		}
	}

	return catalog.ProfFeatScore{
		Score:  score,
		Desc:   desc,
		Ignore: false,
	}
}

// NTIA2025 Component Hash - Enhanced requirement for NTIA 2025
func NTIA2025CompHash(doc sbom.Document) catalog.ProfFeatScore {
	total := len(doc.Components())
	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   formulae.NoComponentsNA(),
			Ignore: false,
		}
	}

	have := 0
	for _, comp := range doc.Components() {
		checksums := comp.GetChecksums()
		if len(checksums) > 0 {
			have++
		}
	}

	score := (float64(have) / float64(total)) * 10.0

	return catalog.ProfFeatScore{
		Score:  score,
		Desc:   formulae.CompDescription(have, total),
		Ignore: false,
	}
}

// NTIA2025 License - Required for all components in NTIA 2025
func NTIA2025CompLicense(doc sbom.Document) catalog.ProfFeatScore {
	total := len(doc.Components())
	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   formulae.NoComponentsNA(),
			Ignore: false,
		}
	}

	have := 0
	for _, comp := range doc.Components() {
		hasLicense := false
		// Check for concluded license
		if concluded := comp.ConcludedLicenses(); concluded != nil {
			for _, lic := range concluded {
				if lic.ShortID() != "" || lic.Name() != "" {
					hasLicense = true
					break
				}
			}
		}
		// Check for declared license
		if !hasLicense {
			if declared := comp.DeclaredLicenses(); declared != nil {
				for _, lic := range declared {
					if lic.ShortID() != "" || lic.Name() != "" {
						hasLicense = true
						break
					}
				}
			}
		}
		if hasLicense {
			have++
		}
	}

	score := (float64(have) / float64(total)) * 10.0

	return catalog.ProfFeatScore{
		Score:  score,
		Desc:   formulae.CompDescription(have, total),
		Ignore: false,
	}
}

// NTIA2025 Software Identifiers - Enhanced requirement for NTIA 2025
func NTIA2025CompSoftwareIdentifiers(doc sbom.Document) catalog.ProfFeatScore {
	total := len(doc.Components())
	if total == 0 {
		return catalog.ProfFeatScore{
			Score:  0.0,
			Desc:   formulae.NoComponentsNA(),
			Ignore: false,
		}
	}

	have := 0
	spec := doc.Spec().GetSpecType()

	for _, comp := range doc.Components() {
		hasId := false

		if spec == string(sbom.SBOMSpecSPDX) {
			// Check for SPDX ID first
			if spdxID := comp.GetSpdxID(); spdxID != "" {
				hasId = true
			} else {
				// Check for PURL in external references
				if extRefs := comp.ExternalReferences(); extRefs != nil {
					for _, extRef := range extRefs {
						if extRef.GetRefType() == "purl" {
							hasId = true
							break
						}
					}
				}
			}
		} else if spec == string(sbom.SBOMSpecCDX) {
			// Check for PURLs, CPEs, or SWIDs
			if purls := comp.GetPurls(); len(purls) > 0 {
				hasId = true
			} else if cpes := comp.GetCpes(); len(cpes) > 0 {
				hasId = true
			}
		}

		if hasId {
			have++
		}
	}

	score := (float64(have) / float64(total)) * 10.0

	return catalog.ProfFeatScore{
		Score:  score,
		Desc:   formulae.CompDescription(have, total),
		Ignore: false,
	}
}
