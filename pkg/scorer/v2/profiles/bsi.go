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
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
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
func specWithVersionCompliant(doc sbom.Document) ProfileFeatureScore {
	spec := strings.ToLower(strings.TrimSpace(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	switch spec {
	case "spdx":
		if lo.Contains(validBsiSpdxVersions, ver) {
			return ProfileFeatureScore{Score: 10.0, Desc: fmt.Sprintf("supported: %s %s", spec, ver)}
		}
		return ProfileFeatureScore{Score: 5.0, Desc: fmt.Sprintf("spec supported but not version: %s", ver)}
	case "cyclonedx":
		if lo.Contains(validBsiCdxVersions, ver) {
			return ProfileFeatureScore{Score: 10.0, Desc: fmt.Sprintf("supported: %s %s", spec, ver)}
		}
		return ProfileFeatureScore{Score: 5.0, Desc: fmt.Sprintf("spec supported but not version: %s", ver)}
	default:
		return ProfileFeatureScore{Score: 0.0, Desc: fmt.Sprintf("unsupported spec: %s", spec)}
	}
}

// sbomWithURICheck
func sbomWithURICheck(doc sbom.Document) ProfileFeatureScore {
	if strings.TrimSpace(doc.Spec().GetURI()) == "" {
		return ProfileFeatureScore{Score: 0.0, Desc: "no URI", Ignore: false}
	}
	return ProfileFeatureScore{Score: 10.0, Desc: "has URI", Ignore: false}
}

// bsiCompWithUniqIDCheck
// BSI wants “unique identifiers” usable for vuln lookup: PURL or CPE.
func bsiCompWithUniqIDCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return len(c.GetPurls()) > 0 || len(c.GetCpes()) > 0
	})

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   formulae.CompDescription(have, len(comps), "unique IDs (purl/cpe)"),
		Ignore: false,
	}
}

// compWithLicensesCompliantCheck (generic “valid licenses” per component)
func compWithLicensesCompliantCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	// NOTE: keeping prior behavior: “valid licenses” on the component license set.
	with := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return AreLicensesValid(c.GetLicenses()) // keep your common.AreLicensesValid impl under this name
	})

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "compliant licenses"),
		Ignore: false,
	}
}

// compWithDependencyCheck: components that have any relationships/dependencies
func compWithDependencyCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return c.HasRelationShips() })

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "dependencies"),
		Ignore: false,
	}
}

// compWithSHA256ChecksumsCheck: components that have SHA-256 (or variants) checksum
func compWithSHA256ChecksumsCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	algos := []string{"SHA256", "SHA-256", "sha256", "sha-256"}
	with := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return lo.ContainsBy(c.GetChecksums(), func(cs sbom.GetChecksum) bool {
			return lo.Contains(algos, cs.GetAlgo())
		})
	})

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "SHA-256+ checksums"),
		Ignore: false,
	}
}

// compWithSourceCodeURICheck: NA for SPDX; CDX requires externalReferences(type=vcs) or similar
func compWithSourceCodeURICheck(doc sbom.Document) ProfileFeatureScore {
	if strings.ToLower(doc.Spec().GetSpecType()) == "spdx" {
		return ProfileFeatureScore{Score: 0.0, Desc: formulae.NonSupportedSPDXField(), Ignore: true}
	}

	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return strings.TrimSpace(c.GetSourceCodeURL()) != "" })

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "source code URIs"),
		Ignore: false,
	}
}

// compWithExecutableURICheck
func compWithExecutableURICheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return strings.TrimSpace(c.GetDownloadLocationURL()) != "" })

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "executable URIs"),
		Ignore: false,
	}
}

// compWithSourceCodeHashCheck: NA for CycloneDX (not deterministic there, per your note)
func compWithSourceCodeHashCheck(doc sbom.Document) ProfileFeatureScore {
	if strings.ToLower(doc.Spec().GetSpecType()) == "cyclonedx" {
		return ProfileFeatureScore{Score: 0.0, Desc: "N/A (CycloneDX)", Ignore: true}
	}

	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return strings.TrimSpace(c.SourceCodeHash()) != "" })

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "source code hashes"),
		Ignore: false,
	}
}

// sbomWithBomLinksCheck
func sbomWithBomLinksCheck(doc sbom.Document) ProfileFeatureScore {
	links := doc.Spec().GetExtDocRef()
	if len(links) == 0 {
		return ProfileFeatureScore{Score: 0.0, Desc: "no bom links found", Ignore: false}
	}
	return ProfileFeatureScore{Score: 10.0, Desc: fmt.Sprintf("found %d bom links", len(links)), Ignore: false}
}

// sbomWithVulnCheck (BSI v2.1 note in your comments)
// If SPDX has no deterministic vuln field → mark NA for SPDX (clearer than awarding 10).
func sbomWithVulnCheck(doc sbom.Document) ProfileFeatureScore {
	if strings.ToLower(doc.Spec().GetSpecType()) == "spdx" {
		return ProfileFeatureScore{Score: 0.0, Desc: formulae.NonSupportedSPDXField(), Ignore: true}
	}

	vulns := doc.Vulnerabilities()
	hasAny := false
	var ids []string
	for _, v := range vulns {
		if id := strings.TrimSpace(v.GetID()); id != "" {
			hasAny = true
			ids = append(ids, id)
		}
	}

	if hasAny {
		return ProfileFeatureScore{Score: 0.0, Desc: "vulnerabilities found: " + strings.Join(ids, ", "), Ignore: false}
	}
	return ProfileFeatureScore{Score: 10.0, Desc: "no vulnerabilities found", Ignore: false}
}

// sbomBuildLifecycleCheck: NA for SPDX; in CDX, look for "build" lifecycle.
func sbomBuildLifecycleCheck(doc sbom.Document) ProfileFeatureScore {
	if strings.ToLower(doc.Spec().GetSpecType()) == "spdx" {
		return ProfileFeatureScore{Score: 0.0, Desc: formulae.NonSupportedSPDXField(), Ignore: true}
	}

	lifecycles := doc.Lifecycles()
	foundBuild := lo.Count(lifecycles, "build") > 0
	if foundBuild {
		return ProfileFeatureScore{Score: 10.0, Desc: "lifecycle includes build", Ignore: false}
	}
	return ProfileFeatureScore{Score: 0.0, Desc: "no build phase in lifecycle", Ignore: false}
}

// sbomWithSignatureCheck
// NOTE: Prefer to move the crypto verification into a small helper (no file I/O here).
// Here we keep the shape and return NA if no signature provided.
func sbomWithSignatureCheck(doc sbom.Document) ProfileFeatureScore {
	sig := doc.Signature()
	if sig == nil {
		return ProfileFeatureScore{Score: 0.0, Desc: "no signature provided", Ignore: true}
	}

	pubKeyPath := strings.TrimSpace(sig.GetPublicKey())
	blobPath := strings.TrimSpace(sig.GetBlob())
	sigPath := strings.TrimSpace(sig.GetSigValue())

	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return ProfileFeatureScore{Score: 0.0, Desc: "public key not readable", Ignore: false}
	}

	valid, verr := VerifySignature(pubKeyData, blobPath, sigPath) // implement elsewhere
	if verr != nil {
		return ProfileFeatureScore{Score: 0.0, Desc: "signature verification failed", Ignore: false}
	}
	if valid {
		return ProfileFeatureScore{Score: 10.0, Desc: "signature verified", Ignore: false}
	}
	return ProfileFeatureScore{Score: 5.0, Desc: "signature provided but invalid", Ignore: false}
}

// compWithAssociatedLicensesCheck: concluded for SPDX, effective for CDX components
func compWithAssociatedLicensesCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	spec := strings.ToLower(doc.Spec().GetSpecType())
	var with int
	switch spec {
	case "spdx":
		with = lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.ConcludedLicenses()) })
	case "cyclonedx":
		with = lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.GetLicenses()) })
	default:
		// treat unknown spec as NA
		return ProfileFeatureScore{Score: 0.0, Desc: formulae.UnknownSpec(), Ignore: true}
	}

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "associated licenses"),
		Ignore: false,
	}
}

// compWithConcludedLicensesCheck (SPDX)
func compWithConcludedLicensesCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.ConcludedLicenses()) })

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "compliant concluded licenses"),
		Ignore: false,
	}
}

// compWithDeclaredLicensesCheck
func compWithDeclaredLicensesCheck(doc sbom.Document) ProfileFeatureScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return ProfileFeatureScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.DeclaredLicenses()) })

	return ProfileFeatureScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "compliant declared licenses"),
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
