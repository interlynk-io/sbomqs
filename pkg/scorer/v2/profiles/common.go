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
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	commonV2 "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// SBOMSpec checks whether the SBOM has a standard specification (SPDX or CycloneDX)
// and then assigns a corresponding score.
func SBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == "" {
		return formulae.ScoreSBOMProfMissingNA("spec", false)
	}

	for _, s := range sbom.SupportedSBOMSpecs() {
		if spec == strings.ToLower(strings.TrimSpace(s)) {
			return formulae.ScoreSBOMProfFull(spec, false)
		}
	}

	return formulae.ScoreSBOMProfNA(fmt.Sprintf("unsupported spec: %s", spec), false)
}

// SBOMSpecVersion checks whether the SBOM's specification version is present
// and supported for the given spec (e.g., SPDX or CycloneDX) and assigns a score.
func SBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == "" {
		return formulae.ScoreSBOMProfMissingNA("spec", false)
	}

	if ver == "" {
		return formulae.ScoreSBOMProfMissingNA("version", false)
	}

	supportedVersions := sbom.SupportedSBOMSpecVersions(spec)
	for _, v := range supportedVersions {
		if ver == v {
			return formulae.ScoreSBOMProfFull(ver, false)
		}
	}

	return formulae.ScoreSBOMProfNA(fmt.Sprintf("unsupported spec version: %s (spec %s)", ver, spec), false)
}

// SBOMAutomationSpec checks whether the SBOM's file format is present
// and supported for the given specification (e.g., SPDX or CycloneDX)
// and assigns an appropriate score.
func SBOMAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	format := strings.TrimSpace(strings.ToLower(doc.Spec().FileFormat()))

	if spec == "" {
		return formulae.ScoreSBOMProfMissingNA("spec", false)
	}

	if format == "" {
		return formulae.ScoreSBOMProfMissingNA("file format", false)
	}

	supportedFileFormats := sbom.SupportedSBOMFileFormats(spec)
	for _, f := range supportedFileFormats {
		if format == strings.ToLower(strings.TrimSpace(f)) {
			return formulae.ScoreSBOMProfFull(format, false)
		}
	}

	return formulae.ScoreSBOMProfNA(fmt.Sprintf("unsupported file format: %s (spec %s)", format, spec), false)
}

// SBOMSchema checks whether the SBOM document has valid schema for
// spdx/cyclonedsx spec or not and then score accordingly
func SBOMSchema(doc sbom.Document) catalog.ProfFeatScore {
	if doc.SchemaValidation() {
		return formulae.ScoreSBOMProfFull("valid schema", false)
	}

	return formulae.ScoreSBOMProfNA("invalid schema", false)
}

// SBOMLifeCycle check whether cyclonedx has lifecycle build
// and score accordingly
// SPDX doesn't support this field
func SBOMLifeCycle(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: true,
		}

	case string(sbom.SBOMSpecCDX):
		var phases []string

		for _, p := range doc.Lifecycles() {
			if strings.TrimSpace(p) != "" {
				phases = append(phases, p)
			}
		}

		if len(phases) > 0 {
			return formulae.ScoreSBOMProfFull(strings.Join(phases, ", "), false)
		}

		return formulae.ScoreSBOMProfMissingNA("lifecycle", false)
	}
	return formulae.ScoreSBOMProfUnknownNA("lifecycle", false)
}

// SBOMNamespace check whether spdx has namespace
// and cyclonedx has serialNumber and score accordingly
// `Namespace` for SPDX, `serial/version` for CDX
func SBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	uri := strings.TrimSpace(doc.Spec().GetURI())
	if uri != "" {
		return formulae.ScoreSBOMProfFull("namespace", false)
	}

	return formulae.ScoreSBOMProfMissingNA("namespace", false)
}

// SBOMAuthor represents an legal entity created an SBOM.
// SPDX: Creator.(Person/Organization); CDX: metadata.(authors/supplier)
func SBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	total := len(doc.Authors())

	if total == 0 {
		return formulae.ScoreSBOMProfMissingNA("authors", false)
	}

	if commonV2.IsSBOMAuthorEntity(doc) {
		return formulae.ScoreSBOMProfFull(fmt.Sprintf("%d legal authors", total), false)
	}

	return formulae.ScoreSBOMProfMissingNA("legal authors", false)
}

// SBOMSupplier: CDX-only (supplier/manufacturer in metadata).
// SPDX has no doc-level supplier,  N/A for SPDX.
// For CDX: missing supplier is a FAIL (score 0, Ignore=false).
func SBOMSupplier(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		// N/A for SPDX
		return formulae.ScoreSBOMProfMissingNA("authors", false)

	case string(sbom.SBOMSpecCDX):
		s := doc.Supplier()
		if s != nil {
			hasName := strings.TrimSpace(s.GetName()) != ""
			hasContact := strings.TrimSpace(s.GetEmail()) != "" || strings.TrimSpace(s.GetURL()) != ""

			if hasName && hasContact {
				return formulae.ScoreSBOMProfFull("1 supplier", false)
			}
		}

		return formulae.ScoreSBOMProfMissingNA("supplier", false)

	}

	// Unknown spec → treat as not applicable to be safe (optional)
	return formulae.ScoreSBOMProfUnknownNA("lifecycle", false)
}

// SBOMCreationTime check has a valid ISO-8601 timestamp (RFC3339/RFC3339Nano).
// `Created` for SPDX and `metadata.timestamp` for CDX
func SBOMCreationTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return formulae.ScoreSBOMProfMissingNA("timestamp", false)
	}

	// accept both RFC3339 and RFC3339Nano
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, ts); err2 != nil {
			return formulae.ScoreSBOMProfNA(fmt.Sprintf("invalid timestamp: %s", ts), false)
		}
	}

	return formulae.ScoreSBOMProfFull(ts, false)
}

// SBOMDepedencies checks for primary component level dependencies
// SPDX: relationships (DEPENDS_ON); CDX: component.dependencies / bom.dependencies
func SBOMDepedencies(doc sbom.Document) catalog.ProfFeatScore {
	var have int
	if doc.PrimaryComp() != nil {
		have = doc.PrimaryComp().GetTotalNoOfDependencies()
	}

	if have == 0 {
		return formulae.ScoreSBOMProfMissingNA("dependencies", false)
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   "complete",
		Ignore: false,
	}
}

// CompName: percentage of components that have a non-empty name.
// Package.Name for SPDX, Compnent.Name for CDX
func CompName(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetName()) != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "name", false)
}

// CompVersion: percentage of components that have a non-empty version.
func CompVersion(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "versions", false)
}

func CompSupplier(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return commonV2.IsSupplierEntity(c.Suppliers())
	})

	return formulae.ScoreProfFull(have, len(comps), "names", false)
}

// // isSupplierEntity check whether supplier is a legal entity or not:
// // supplier should have either name/email/url/contact info.
// func isSupplierEntity(supplier sbom.GetSupplier) bool {
// 	if supplier.GetName() != "" || supplier.GetEmail() != "" {
// 		return true
// 	}
// 	return false
// }

// CompLicenses check for concluded valid license and score accordingly
func CompLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyConcluded(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "licenses", false)
}

// CompConcludedLicenses check for concluded valid license and score accordingly
func CompConcludedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyConcluded(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "licenses", false)
}

// CompHash returns coverage of components that have SHA-1 or stronger
// (MD5, SHA-1, SHA-256, SHA-384, or SHA-512).
func CompHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.HasSHA1Plus(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "hash", false)
}

// CompWithSHA256Plus returns coverage of components that have SHA-256 or stronger.
func CompSHA256Plus(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := 0
	for _, c := range comps {
		if commonV2.HasSHA256Plus(c) {
			have++
		}
	}

	return formulae.ScoreProfFull(have, len(comps), "SHA-256+", false)
}

// CompSourceCodeURL checks source code repo url
// `PackageSourceInfo` for SPDX Ext Ref type `VCS` for CDX
func CompSourceCodeURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return commonV2.HasComponentSourceCodeURL(c.GetSourceCodeURL())
	})

	return formulae.ScoreProfFull(have, len(comps), "source code repo", true)
}

// CompCopyright
func CompCopyright(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		dl := strings.ToLower(strings.TrimSpace(c.GetCopyRight()))
		return dl != "" && dl != "none" && dl != "noassertion"
	})

	return formulae.ScoreProfFull(have, len(comps), "copyright", true)
}

// CompDownloadCodeURL checks download url
// `PackageDownloadLocation` for SPDX, Ext Ref type `distribution-vcs` url for CDX
func CompDownloadCodeURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetDownloadLocationURL()) != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "download URIs", false)
}

// CompSourceCodeHash checks for source code has
// `PackageVerificationCode` for SPDX, no determinsitic field in CDX
func CompSourceCodeHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == string(sbom.SBOMSpecCDX) {
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(true),
			Desc:   "no-deterministic-field",
			Ignore: true,
		}
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.SourceCodeHash() != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "source code hash", true)
}

// CompDependencies checks for component level dependencies
// SPDX: relationships (DEPENDS_ON); CDX: component.dependencies / bom.dependencies
func CompDependencies(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.HasComponentDependencies(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "dependencies", false)
}

func CompUniqID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return checkUniqueID(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "unique ID", false)
}

func CompPURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.CompHasAnyPURLs(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "PURLs", false)
}

func CompCPE(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.CompHasAnyCPEs(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "CPEs", false)
}

func CompPurpose(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.HasComponentPrimaryPackageType(c.PrimaryPurpose())
	})

	return formulae.ScoreProfFull(have, len(comps), "type", false)
}

func CompWithNODeprecatedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyDeprecated(c)
	})

	description := fmt.Sprintf("%d deprecated", have)
	if have == 0 {
		description = "N/A"
	}

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   description,
		Ignore: false,
	}
}

func CompWithNORestrictiveLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyRestrictive(c)
	})

	description := fmt.Sprintf("%d restrictive", have)
	if have == 0 {
		description = "N/A"
	}

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(have, len(comps)),
		Desc:   description,
		Ignore: false,
	}
}

// checkUniqueID checks for PURL/CPE
func checkUniqueID(c sbom.GetComponent) bool {
	if commonV2.CompHasAnyPURLs(c) {
		return true
	}

	if commonV2.CompHasAnyCPEs(c) {
		return true
	}

	return false
}

// CompDeclaredLicenses look for declared licenses
func CompDeclaredLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return commonV2.ComponentHasAnyDeclared(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "declared license", false)
}

// SBOMSignature look for signature
func SBOMSignature(doc sbom.Document) catalog.ProfFeatScore {
	sig := doc.Signature()
	if sig == nil {
		return formulae.ScoreSBOMProfMissingNA("signature", false)
	}

	// Check if signature has the required components
	algorithm := strings.TrimSpace(sig.GetAlgorithm())
	sigValue := strings.TrimSpace(sig.GetSigValue())
	
	// Incomplete signature → treat as missing
	if algorithm == "" || sigValue == "" {
		return formulae.ScoreSBOMProfMissingNA("signature", false)
	}
	
	// Check if we have public key or certificate path for verification
	pubKey := strings.TrimSpace(sig.GetPublicKey())
	certPath := sig.GetCertificatePath()
	
	if pubKey == "" && len(certPath) == 0 {
		// Signature present but no verification material
		return catalog.ProfFeatScore{
			Score:  5.0, // signature present, but no verification key
			Desc:   "signature present but no verification key",
			Ignore: false,
		}
	}
	
	// For now, we'll give full score if signature is complete
	// Future enhancement: actually verify the signature
	return catalog.ProfFeatScore{
		Score:  10.0,
		Desc:   "signature present with verification material",
		Ignore: false,
	}
}

func SBOMVulnerabilities(doc sbom.Document) catalog.ProfFeatScore {
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
		return catalog.ProfFeatScore{Score: 0.0, Desc: "vulnerabilities found: " + strings.Join(ids, ", "), Ignore: true}
	}

	return formulae.ScoreSBOMProfFull("no vulnerabilities", true)
}

func SBOMPrimaryComponent(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()

	if !commonV2.HasSBOMPrimaryComponent(doc) {
		return catalog.ProfFeatScore{
			Score:  formulae.PerComponentScore(0, len(comps)),
			Desc:   "absent",
			Ignore: true,
		}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(commonV2.HasSBOMPrimaryComponent(doc)),
		Desc:   "present",
		Ignore: false,
	}
}

func SBOMCompleteness(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: true,
		}

	case string(sbom.SBOMSpecCDX):
		// TODO: to add this method in our sbom module, then only we can fetch it here
		// Compositions/Aggregate
		// have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		// 	return c.GetComposition() != ""
		// })
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("completeness"),
			Ignore: true,
		}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}

func SBOMDataLicense(doc sbom.Document) catalog.ProfFeatScore {
	specLicenses := doc.Spec().GetLicenses()

	if len(specLicenses) == 0 {
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("data license"),
			Ignore: false,
		}
	}

	if commonV2.AreLicensesValid(specLicenses) {
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(true),
			Desc:   formulae.PresentField("data license"),
			Ignore: false,
		}
	}
	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   "invalid data license",
		Ignore: false,
	}
}

func SBOMTool(doc sbom.Document) catalog.ProfFeatScore {
	toolsWithNV := make([]string, 0, len(doc.Tools()))

	for _, t := range doc.Tools() {
		name := strings.TrimSpace(t.GetName())
		ver := strings.TrimSpace(t.GetVersion())

		if name != "" && ver != "" {
			toolsWithNV = append(toolsWithNV, name+"-"+ver)
		}
	}

	if len(toolsWithNV) == 0 {
		return catalog.ProfFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("tool"),
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("%d tool", len(toolsWithNV)),
		Ignore: false,
	}
}
