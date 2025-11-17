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
	"time"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/knqyf263/go-cpe/naming"
	purl "github.com/package-url/packageurl-go"
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

	if isSBOMAuthorEntity(doc) {
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

// isSBOMAuthorEntity check whether author is a legal entity or not:
// author should have name + email/phone info.
func isSBOMAuthorEntity(doc sbom.Document) bool {
	for _, author := range doc.Authors() {
		if author.GetName() != "" && (author.GetEmail() != "" || author.GetPhone() != "") {
			return true
		}
	}
	return false
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

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("primary comp has %d dependencies", have),
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
		return isSupplierEntity(c.Suppliers())
	})

	return formulae.ScoreProfFull(have, len(comps), "names", false)
}

// isSupplierEntity check whether supplier is a legal entity or not:
// supplier should have name + email/url/contact info.
func isSupplierEntity(supplier sbom.GetSupplier) bool {
	if supplier.GetName() != "" && (supplier.GetEmail() != "" || supplier.GetURL() != "" || len(supplier.GetContacts()) > 0) {
		return true
	}
	return false
}

// CompLicenses check for concluded valid license and score accordingly
func CompLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return componentHasAnyConcluded(c)
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
		return componentHasAnyConcluded(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "licenses", false)
}

func componentHasAnyConcluded(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if id := strings.TrimSpace(l.ShortID()); validateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); validateLicenseText(nm) {
			return true
		}
	}
	return false
}

// license with "NOASSERTION" or "NONE" are considered as
// non-meaningful licenses
func validateLicenseText(s string) bool {
	if s == "" {
		return false
	}

	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "NOASSERTION" || u == "NONE" {
		return false
	}
	return true
}

// CompHash returns coverage of components that have SHA-1 or stronger
// (MD5, SHA-1, SHA-256, SHA-384, or SHA-512).
func CompHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return hasAnySHA(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "hash", false)
}

func hasAnySHA(c sbom.GetComponent) bool {
	for _, checksum := range c.GetChecksums() {
		if isAnySHA(checksum.GetAlgo()) && strings.TrimSpace(checksum.GetContent()) != "" {
			return true
		}
	}
	return false
}

func isAnySHA(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	switch n {
	case "SHA1", "SHA256", "SHA384", "SHA512", "MD5":
		return true
	default:
		return false
	}
}

// CompHash returns coverage of components that have SHA-1 or stronger
// (MD5, SHA-1, SHA-256, SHA-384, or SHA-512).
func CompSHA256(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return hasSHA256SHA(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "hash256", false)
}

func hasSHA256SHA(c sbom.GetComponent) bool {
	for _, checksum := range c.GetChecksums() {
		if isSHA256(checksum.GetAlgo()) && strings.TrimSpace(checksum.GetContent()) != "" {
			return true
		}
	}
	return false
}

func isSHA256(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	if n == "SHA256" {
		return true
	}
	return false
}

// CompWithSHA256Plus returns coverage of components that have SHA-256 or stronger.
func CompSHA256Plus(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := 0
	for _, c := range comps {
		if hasSHA256Plus(c) {
			have++
		}
	}

	return formulae.ScoreProfFull(have, len(comps), "SHA-256+", false)
}

func hasSHA256Plus(c sbom.GetComponent) bool {
	for _, ch := range c.GetChecksums() {
		if isSHA256Plus(ch.GetAlgo()) && strings.TrimSpace(ch.GetContent()) != "" {
			return true
		}
	}
	return false
}

func isSHA256Plus(algo string) bool {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)

	switch n {
	case "SHA256", "SHA384", "SHA512":
		return true
	default:
		return false
	}
}

// CompSourceCodeURL checks source code repo url
// `PackageSourceInfo` for SPDX Ext Ref type `VCS` for CDX
func CompSourceCodeURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetSourceCodeURL()) != ""
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
		return c.HasRelationShips() || c.CountOfDependencies() > 0
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
		return compHasAnyPURLs(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "PURLs", false)
}

func CompCPE(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return compHasAnyCPEs(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "CPEs", false)
}

func compHasAnyPURLs(c sbom.GetComponent) bool {
	for _, p := range c.GetPurls() {
		if isValidPURL(string(p)) {
			return true
		}
	}
	return false
}

func compHasAnyCPEs(c sbom.GetComponent) bool {
	for _, p := range c.GetCpes() {
		if isValidCPE(string(p)) {
			return true
		}
	}
	return false
}

func CompPurpose(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return c.PrimaryPurpose() != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "type", false)
}

func CompWithNODeprecatedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return componentHasAnyDeprecated(c)
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

func componentHasAnyDeprecated(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Deprecated() {
			return true
		}
	}
	return false
}

func CompWithNORestrictiveLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return componentHasAnyRestrictive(c)
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

func componentHasAnyRestrictive(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Restrictive() {
			return true
		}
	}
	return false
}

func checkUniqueID(c sbom.GetComponent) bool {
	for _, p := range c.GetPurls() {
		if isValidPURL(string(p)) {
			return true
		}
	}

	for _, p := range c.GetCpes() {
		if isValidCPE(string(p)) {
			return true
		}
	}
	return false
}

func isValidCPE(s string) bool {
	ls := strings.TrimSpace(s)
	low := strings.ToLower(ls)

	switch {
	case strings.HasPrefix(low, "cpe:2.3:"):
		_, err := naming.UnbindFS(ls)
		return err == nil
	case strings.HasPrefix(low, "cpe:/"):
		_, err := naming.UnbindURI(ls)
		return err == nil
	default:
		return false
	}
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

// CompDeclaredLicenses look for declared licenses
func CompDeclaredLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA(true)
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return componentHasAnyDeclared(c)
	})

	return formulae.ScoreProfFull(have, len(comps), "declared license", false)
}

func componentHasAnyDeclared(c sbom.GetComponent) bool {
	for _, l := range c.DeclaredLicenses() {
		if id := strings.TrimSpace(l.ShortID()); validateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); validateLicenseText(nm) {
			return true
		}
	}
	return false
}

// SBOMSignature look for signature
func SBOMSignature(doc sbom.Document) catalog.ProfFeatScore {
	sig := doc.Signature()
	if sig == nil {
		return formulae.ScoreSBOMProfMissingNA("signature", false)
	}

	pubKeyPath := strings.TrimSpace(sig.GetPublicKey())
	blobPath := strings.TrimSpace(sig.GetBlob())
	sigPath := strings.TrimSpace(sig.GetSigValue())

	// Incomplete bundle → treat as missing
	if pubKeyPath == "" || blobPath == "" || sigPath == "" {
		return formulae.ScoreSBOMProfMissingNA("signature bundle", false)
	}

	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return catalog.ProfFeatScore{
			Score:  5.0, // bundle present, but verification cannot succeed
			Desc:   fmt.Sprintf("cannot read public key: %v", err),
			Ignore: false,
		}
	}

	ok, err := common.VerifySignature(pubKeyBytes, blobPath, sigPath)
	if err != nil {
		return catalog.ProfFeatScore{
			Score:  5.0,
			Desc:   "signature present but verification failed",
			Ignore: false,
		}
	}
	if ok {
		return catalog.ProfFeatScore{
			Score:  10.0,
			Desc:   "signature verification succeeded",
			Ignore: false,
		}
	}

	return catalog.ProfFeatScore{
		Score:  5.0,
		Desc:   "signature present but invalid",
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
	isPrimaryPresent := doc.PrimaryComp().IsPresent()

	if !isPrimaryPresent {
		return catalog.ProfFeatScore{
			Score:  formulae.PerComponentScore(0, len(comps)),
			Desc:   "absent",
			Ignore: true,
		}
	}

	return catalog.ProfFeatScore{
		Score:  formulae.BooleanScore(isPrimaryPresent),
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

	if areLicensesValid(specLicenses) {
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

func areLicensesValid(licenses []licenses.License) bool {
	if len(licenses) == 0 {
		return false
	}
	var spdx, aboutcode, custom int

	for _, license := range licenses {
		switch license.Source() {
		case "spdx":
			spdx++
		case "aboutcode":
			aboutcode++
		case "custom":
			if strings.HasPrefix(license.ShortID(), "LicenseRef-") || strings.HasPrefix(license.Name(), "LicenseRef-") {
				custom++
			}
		}
	}
	return spdx+aboutcode+custom == len(licenses)
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
