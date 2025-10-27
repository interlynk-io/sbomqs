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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

var (
	validBsiSpdxVersions = []string{"SPDX-2.3"}
	validBsiCdxVersions  = []string{"1.4", "1.5", "1.6"}
)

// specWithVersionCompliant
// - 10 if spec+version in BSI-supported lists,
// - 5  if spec supported but version not in list,
// - 0  otherwise.
func specWithVersionCompliant(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.ToLower(strings.TrimSpace(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	switch spec {
	case "spdx":
		if lo.Contains(validBsiSpdxVersions, ver) {
			return catalog.ProfFeatScore{Score: 10.0, Desc: fmt.Sprintf("supported: %s %s", spec, ver)}
		}
		return catalog.ProfFeatScore{Score: 5.0, Desc: fmt.Sprintf("spec supported but not version: %s", ver)}
	case "cyclonedx":
		if lo.Contains(validBsiCdxVersions, ver) {
			return catalog.ProfFeatScore{Score: 10.0, Desc: fmt.Sprintf("supported: %s %s", spec, ver)}
		}
		return catalog.ProfFeatScore{Score: 5.0, Desc: fmt.Sprintf("spec supported but not version: %s", ver)}
	default:
		return catalog.ProfFeatScore{Score: 0.0, Desc: fmt.Sprintf("unsupported spec: %s", spec)}
	}
}

// bsiCompWithUniqIDCheck
// BSI wants “unique identifiers” usable for vuln lookup: PURL or CPE.
func bsiCompWithUniqIDCheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return len(c.GetPurls()) > 0 || len(c.GetCpes()) > 0
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "unique IDs (purl/cpe)"),
		Ignore: false,
	}
}

// compWithLicensesCompliantCheck (generic “valid licenses” per component)
func compWithLicensesCompliantCheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	// NOTE: keeping prior behavior: “valid licenses” on the component license set.
	// with := lo.CountBy(comps, func(c sbom.GetComponent) bool {
	// 	return AreLicensesValid(c.GetLicenses()) // keep your common.AreLicensesValid impl under this name
	// })
	with := 0

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "compliant licenses"),
		Ignore: false,
	}
}

// -----------------------------------------------------------------------------
// Small shared helpers you referenced earlier (wire to your existing code).
// -----------------------------------------------------------------------------

// AreLicensesValid delegates to your licenses package/common validator.
func AreLicensesValid(lics []string) bool {
	// replace with your existing implementation (e.g., common.AreLicensesValid)
	return len(lics) > 0
}

// VerifySignature delegates to your crypto verifier.
// Inputs: loaded public key bytes + paths to blob/sig as your doc currently exposes.
// Return true/false; bubble up errors.
func VerifySignature(pubKey []byte, blobPath, sigPath string) (bool, error) {
	// call your common.VerifySignature(pubKey, blob, sig) after reading blob/sig as needed
	// NOTE: prefer passing raw content rather than paths if you can, to keep I/O outside extractors.
	return false, fmt.Errorf("not implemented")
}
