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
	"time"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

func isSPDX(doc sbom.Document) bool {
	return strings.EqualFold(strings.TrimSpace(doc.Spec().GetSpecType()), string(sbom.SBOMSpecSPDX))
}

func rfc3339ish(ts string) bool {
	if ts == "" {
		return false
	}
	if _, err := time.Parse(time.RFC3339, ts); err == nil {
		return true
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return true
	}
	return false
}

// SBOM Format
func OCTSBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpec(doc)
}

// Spec Version
func OCTSBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpecVersion(doc)
}

// SPDX ID
func OCTSBOMSpdxID(doc sbom.Document) catalog.ProfFeatScore {
	id := strings.TrimSpace(doc.Spec().GetSpdxID())
	if id == "" {
		return formulae.ScoreSBOMProfMissingNA("spdxid", false)
	}

	return formulae.ScoreSBOMProfFull("spdxid", false)
}

// OCTSBOMName: Document Name
func OCTSBOMName(doc sbom.Document) catalog.ProfFeatScore {
	name := strings.TrimSpace(doc.Spec().GetName())
	if name == "" {
		return formulae.ScoreSBOMProfMissingNA("sbom name", false)
	}

	return formulae.ScoreSBOMProfFull("sbom name", false)
}

// OCTSBOMComment: Document Comment
func OCTSBOMComment(doc sbom.Document) catalog.ProfFeatScore {
	com := strings.TrimSpace(doc.Spec().GetComment())
	if com == "" {
		return formulae.ScoreSBOMProfMissingNA("creator comment", true)
	}

	return formulae.ScoreSBOMProfFull("creator comment", true)
}

// Creator Organization
func OCTSBOMCreationOrganization(doc sbom.Document) catalog.ProfFeatScore {
	org := strings.TrimSpace(doc.Spec().GetOrganization())
	if org == "" {
		return formulae.ScoreSBOMProfMissingNA("creator org", true)
	}

	return formulae.ScoreSBOMProfFull("creator org", true)
}

// Creator Tool
func OCTSBOMToolCreation(doc sbom.Document) catalog.ProfFeatScore {
	tools := doc.Tools()
	for _, tool := range tools {
		if tool.GetName() != "" && tool.GetVersion() != "" {
			return formulae.ScoreSBOMProfFull("sbom tool", false)
		}
	}
	return formulae.ScoreSBOMProfMissingNA("sbom tool", false)
}

// OCTSBOMNamespace: Document Namespace
func OCTSBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	ns := strings.TrimSpace(doc.Spec().GetURI())
	if ns == "" {
		return formulae.ScoreSBOMProfMissingNA("namespace", false)
	}

	return formulae.ScoreSBOMProfFull("namespace", false)
}

// OCTSBOMDataLicense: Data License
func OCTSBOMDataLicense(doc sbom.Document) catalog.ProfFeatScore {
	for _, lic := range doc.Spec().GetLicenses() {
		if n := strings.TrimSpace(lic.Name()); n != "" {
			return formulae.ScoreSBOMProfFull("data license", false)
		}
	}
	return formulae.ScoreSBOMProfMissingNA("data license", false)
}

// func OCTSBOMWithTimestamp(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMCreationTimestamp(doc)
// }

// // SPDX JSON or Tag-Value are acceptable “machine/human” forms in OCT.
// func OCTSBOMMachineFormatCheck(doc sbom.Document) catalog.ProfFeatScore {
// 	return SBOMWithAutomationSpec(doc)
// }

// OCTCompWithName: Package Name
func OCTCompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// OCTCompWithVersion: Package Version
func OCTCompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// OCTCompWithSpdxID: Package SPDXID
func OCTCompWithSpdxID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreSBOMProfMissingNA("comp spdxid", false)
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetSpdxID()) != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "comp spdxid", false)
}

// OCTCompWithDownloadURL: Package Download URL
func OCTCompWithDownloadURL(doc sbom.Document) catalog.ProfFeatScore {
	return CompDownloadCodeURL(doc)
}

// OCTCompWithFileAnalyzed: Files Analyzed
func OCTCompWithFileAnalyzed(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return c.GetFileAnalyzed()
	})

	return formulae.ScoreProfFull(have, len(comps), "fileAnalyze", true)
}

// // OCTCompWithSupplier
// func OCTCompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {
// 	return CompSupplier(doc)
// }

// // OctCompWithSHA256Check
// func OctCompWithSHA256Check(doc sbom.Document) catalog.ProfFeatScore {
// 	return CompSHA256(doc)
// }

// OCTCompWithConcludedLicense: Package License Concluded
func OCTCompWithConcludedLicense(doc sbom.Document) catalog.ProfFeatScore {
	return CompConcludedLicenses(doc)
}

// OCTCompWithDeclaredLicense: Package License Declared
func OCTCompWithDeclaredLicense(doc sbom.Document) catalog.ProfFeatScore {
	return CompDeclaredLicenses(doc)
}

// OCTCompWithCopyright: Package Copyright
func OCTCompWithCopyright(doc sbom.Document) catalog.ProfFeatScore {
	return CompCopyright(doc)
}

// // % with copyright (and not NONE/NOASSERTION)
// func OctCompWithExternalRefsCheck(doc sbom.Document) catalog.ProfFeatScore {
// 	comps := doc.Components()
// 	if len(comps) == 0 {
// 		return catalog.ProfFeatScore{
// 			Score:  formulae.PerComponentScore(0, 0),
// 			Desc:   formulae.NoComponentsNA(),
// 			Ignore: true,
// 		}
// 	}

// 	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
// 		// return compHasAnyPURLs(c)
// 		return false
// 	})

// 	return catalog.ProfFeatScore{
// 		Score:  formulae.PerComponentScore(have, len(comps)),
// 		Desc:   formulae.CompDescription(have, len(comps), "declared licenses"),
// 		Ignore: false,
// 	}
// }

// func CompHasAnyPURLs(c sbom.GetComponent) bool {
// 	for _, p := range c.GetPurls() {
// 		if isValidPURL(string(p)) {
// 			return true
// 		}
// 	}
// 	return false
// }

// func isValidPURL(s string) bool {
// 	s = strings.TrimSpace(s)
// 	if s == "" {
// 		return false
// 	}

// 	u, err := purl.FromString(s)
// 	if err != nil {
// 		return false
// 	}

// 	// type and name must be present per spec
// 	if strings.TrimSpace(u.Type) == "" || strings.TrimSpace(u.Name) == "" {
// 		return false
// 	}
// 	return true
// }
