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
	purl "github.com/package-url/packageurl-go"
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

// OCT: must be SPDX
func OCTSBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	ok := isSPDX(doc)
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(ok),
		Desc:   doc.Spec().GetSpecType(),
		Ignore: false,
	}
}

func OCTSBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	ver := strings.TrimSpace(doc.Spec().GetVersion())
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(ver != ""),
		Desc:   ver,
		Ignore: false,
	}
}

func OCTSBOMWithTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if !rfc3339ish(ts) {
		return catalog.ProfFeatScore{Score: 0, Desc: formulae.MissingField("timestamp"), Ignore: false}
	}
	return catalog.ProfFeatScore{Score: 10, Desc: ts, Ignore: false}
}

func OCTSBOMSpdxID(doc sbom.Document) catalog.ProfFeatScore {
	id := strings.TrimSpace(doc.Spec().GetSpdxID())
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(id != ""),
		Desc:   id,
		Ignore: false,
	}
}

func OCTSBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	ns := strings.TrimSpace(doc.Spec().GetNamespace())
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(ns != ""),
		Desc:   ns,
		Ignore: false,
	}
}

func OCTSBOMDataLicense(doc sbom.Document) catalog.ProfFeatScore {
	var names []string
	for _, lic := range doc.Spec().GetLicenses() {
		if n := strings.TrimSpace(lic.Name()); n != "" {
			names = append(names, n)
		}
	}
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(len(names) > 0),
		Desc:   strings.Join(names, ", "),
		Ignore: false,
	}
}

func OCTSBOMToolCreation(doc sbom.Document) catalog.ProfFeatScore {
	tools := doc.Tools()
	ok := len(tools) > 0 && strings.TrimSpace(tools[0].GetName()) != ""
	desc := ""
	if ok {
		desc = tools[0].GetName()
	}
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(ok),
		Desc:   desc,
		Ignore: false,
	}
}

func OCTSBOMCreationOrganization(doc sbom.Document) catalog.ProfFeatScore {
	org := strings.TrimSpace(doc.Spec().GetOrganization())
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(org != ""),
		Desc:   org, // optional in OCT; mark Required=false in spec
		Ignore: false,
	}
}

// SPDX JSON or Tag-Value are acceptable “machine/human” forms in OCT.
func OCTSBOMMachineFormatCheck(doc sbom.Document) catalog.ProfFeatScore {
	ff := strings.ToLower(strings.TrimSpace(doc.Spec().FileFormat()))
	ok := ff == "json" || ff == "tag-value"
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(ok),
		Desc:   ff,
		Ignore: false,
	}
}

// TODO
func OCTSBOMComment(doc sbom.Document) catalog.ProfFeatScore {
	ff := strings.ToLower(strings.TrimSpace(doc.Spec().FileFormat()))
	ok := ff == "json" || ff == "tag-value"
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(ok),
		Desc:   ff,
		Ignore: false,
	}
}

// % with names
func OCTCompWithName(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool { return strings.TrimSpace(c.GetName()) != "" })
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "names"),
		Ignore: false,
	}
}

// % with SPDX IDs
func OCTCompWithSpdxID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool { return strings.TrimSpace(c.GetSpdxID()) != "" })
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "SPDX IDs"),
		Ignore: false,
	}
}

// % with versions
func OCTCompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool { return strings.TrimSpace(c.GetVersion()) != "" })
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "versions"),
		Ignore: false,
	}
}

// % with supplier (OCT requires supplier contact; keep simple: any supplier email/name present)
func OCTCompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		s := c.Suppliers()
		return s.IsPresent() && (strings.TrimSpace(s.GetEmail()) != "" || strings.TrimSpace(s.GetName()) != "")
	})
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "suppliers"),
		Ignore: false,
	}
}

// % with download URL
func OCTCompWithDownloadURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool { return strings.TrimSpace(c.GetDownloadLocationURL()) != "" })
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "download URLs"),
		Ignore: false,
	}
}

// % with SHA-256 (or alias)
func OctCompWithSHA256Check(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return lo.ContainsBy(c.GetChecksums(), func(ch sbom.GetChecksum) bool {
			return lo.Contains(algos, ch.GetAlgo())
		})
	})
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "SHA-256 checksums"),
		Ignore: false,
	}
}

// % with concluded license (and not NONE/NOASSERTION)
func OCTCompWithConcludedLicense(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		cl := strings.TrimSpace(c.GetPackageLicenseConcluded())
		return cl != "" && cl != "NONE" && cl != "NOASSERTION"
	})
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "concluded licenses"),
		Ignore: false,
	}
}

// % with declared license (and not NONE/NOASSERTION)
func OCTCompWithDeclaredLicense(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}
	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		dl := strings.TrimSpace(c.GetPackageLicenseDeclared())
		return dl != "" && dl != "NONE" && dl != "NOASSERTION"
	})
	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "declared licenses"),
		Ignore: false,
	}
}

// % with copyright (and not NONE/NOASSERTION)
func OCTCompWithCopyright(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{
			Score:  formulae.PerComponentScore(0, 0),
			Desc:   formulae.NoComponentsNA(),
			Ignore: true,
		}
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		dl := strings.TrimSpace(c.GetCopyRight())
		return dl != "" && dl != "NONE" && dl != "NOASSERTION"
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "declared licenses"),
		Ignore: false,
	}
}

// % with copyright (and not NONE/NOASSERTION)
func OctCompWithExternalRefsCheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{
			Score:  formulae.PerComponentScore(0, 0),
			Desc:   formulae.NoComponentsNA(),
			Ignore: true,
		}
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		// return compHasAnyPURLs(c)
		return false
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "declared licenses"),
		Ignore: false,
	}
}

// TODO
func OCTCompWithFileAnalyzed(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{
			Score:  formulae.PerComponentScore(0, 0),
			Desc:   formulae.NoComponentsNA(),
			Ignore: true,
		}
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		// return compHasAnyPURLs(c)
		return false
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "declared licenses"),
		Ignore: false,
	}
}

func CompHasAnyPURLs(c sbom.GetComponent) bool {
	for _, p := range c.GetPurls() {
		if isValidPURL(string(p)) {
			return true
		}
	}
	return false
}

func isValidPURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}

	u, err := purl.FromString(s)
	if err != nil {
		return false
	}

	// type and name must be present per spec
	if strings.TrimSpace(u.Type) == "" || strings.TrimSpace(u.Name) == "" {
		return false
	}
	return true
}
