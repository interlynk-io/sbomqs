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
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// sbomWithBomLinksCheck
func SbomWithBomLinksCheck(doc sbom.Document) catalog.ProfFeatScore {
	links := doc.Spec().GetExtDocRef()
	if len(links) == 0 {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no bom links found", Ignore: false}
	}
	return catalog.ProfFeatScore{Score: 10.0, Desc: fmt.Sprintf("found %d bom links", len(links)), Ignore: false}
}

// sbomWithVulnCheck (BSI v2.1 note in your comments)
// If SPDX has no deterministic vuln field → mark NA for SPDX (clearer than awarding 10).
func SbomWithVulnCheck(doc sbom.Document) catalog.ProfFeatScore {
	if strings.ToLower(doc.Spec().GetSpecType()) == "spdx" {
		return catalog.ProfFeatScore{Score: 0.0, Desc: formulae.NonSupportedSPDXField(), Ignore: true}
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
		return catalog.ProfFeatScore{Score: 0.0, Desc: "vulnerabilities found: " + strings.Join(ids, ", "), Ignore: false}
	}
	return catalog.ProfFeatScore{Score: 10.0, Desc: "no vulnerabilities found", Ignore: false}
}

// sbomBuildLifecycleCheck: NA for SPDX; in CDX, look for "build" lifecycle.
func SbomBuildLifecycleCheck(doc sbom.Document) catalog.ProfFeatScore {
	if strings.ToLower(doc.Spec().GetSpecType()) == "spdx" {
		return catalog.ProfFeatScore{Score: 0.0, Desc: formulae.NonSupportedSPDXField(), Ignore: true}
	}

	lifecycles := doc.Lifecycles()
	foundBuild := lo.Count(lifecycles, "build") > 0
	if foundBuild {
		return catalog.ProfFeatScore{Score: 10.0, Desc: "lifecycle includes build", Ignore: false}
	}
	return catalog.ProfFeatScore{Score: 0.0, Desc: "no build phase in lifecycle", Ignore: false}
}

// sbomWithSignatureCheck
// NOTE: Prefer to move the crypto verification into a small helper (no file I/O here).
// Here we keep the shape and return NA if no signature provided.
func SbomWithSignatureCheck(doc sbom.Document) catalog.ProfFeatScore {
	sig := doc.Signature()
	if sig == nil {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "no signature provided", Ignore: true}
	}

	pubKeyPath := strings.TrimSpace(sig.GetPublicKey())
	blobPath := strings.TrimSpace(sig.GetBlob())
	sigPath := strings.TrimSpace(sig.GetSigValue())

	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "public key not readable", Ignore: false}
	}

	valid, verr := VerifySignature(pubKeyData, blobPath, sigPath) // implement elsewhere
	if verr != nil {
		return catalog.ProfFeatScore{Score: 0.0, Desc: "signature verification failed", Ignore: false}
	}
	if valid {
		return catalog.ProfFeatScore{Score: 10.0, Desc: "signature verified", Ignore: false}
	}
	return catalog.ProfFeatScore{Score: 5.0, Desc: "signature provided but invalid", Ignore: false}
}

// compWithAssociatedLicensesCheck: concluded for SPDX, effective for CDX components
func CompWithAssociatedLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	spec := strings.ToLower(doc.Spec().GetSpecType())
	var with int
	switch spec {
	case "spdx":
		// with = lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.ConcludedLicenses()) })
	case "cyclonedx":
		// with = lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.GetLicenses()) })
	default:
		// treat unknown spec as NA
		return catalog.ProfFeatScore{Score: 0.0, Desc: formulae.UnknownSpec(), Ignore: true}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "associated licenses"),
		Ignore: false,
	}
}

// compWithConcludedLicensesCheck (SPDX)
func CompWithConcludedLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := 0
	// with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.ConcludedLicenses()) })

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "compliant concluded licenses"),
		Ignore: false,
	}
}

// compWithDeclaredLicensesCheck
func CompWithDeclaredLicensesCheck(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return catalog.ProfFeatScore{Score: formulae.PerComponentScore(0, 0), Desc: formulae.NoComponentsNA(), Ignore: true}
	}

	with := 0
	// with := lo.CountBy(comps, func(c sbom.GetComponent) bool { return AreLicensesValid(c.DeclaredLicenses()) })

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(with, len(comps)),
		Desc:   formulae.CompDescription(with, len(comps), "compliant declared licenses"),
		Ignore: false,
	}
}
