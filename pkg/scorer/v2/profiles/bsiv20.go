package profiles

import (
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

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
