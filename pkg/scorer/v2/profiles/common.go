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
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// SBOMSpec checks whether the SBOM uses a supported specification (SPDX or CycloneDX)
// and assigns a corresponding score.
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

	if spec == "" || ver == "" {
		return formulae.ScoreSBOMProfMissingNA("spec/version", false)
	}

	supportedVersions := sbom.SupportedSBOMSpecVersions(spec)
	for _, v := range supportedVersions {
		if ver == v {
			return formulae.ScoreSBOMProfFull(ver, false)
		}
	}

	return formulae.ScoreSBOMProfNA(fmt.Sprintf("unsupported version: %s (spec %s)", ver, spec), false)
}

// SBOMAutomationSpec checks whether the SBOM's file format is present
// and supported for the given specification (e.g., SPDX or CycloneDX)
// and assigns an appropriate score.
func SBOMAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	format := strings.TrimSpace(strings.ToLower(doc.Spec().FileFormat()))

	if spec == "" || format == "" {
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

// SBOMLifeCycle check whether cyclonedx has lifecycle build and score accordingly
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
		phases := doc.Lifecycles()
		if len(phases) > 0 {
			return formulae.ScoreSBOMProfFull(strings.Join(phases, ", "), false)
		}

		return formulae.ScoreSBOMProfMissingNA("lifecycle", false)
	}
	return formulae.ScoreSBOMProfUnknownNA("lifecycle", true)
}

// SBOMNamespace check whether spdx has namespace
// and cyclonedx has serialNumber and score accordingly
func SBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		ns := strings.TrimSpace(doc.Spec().GetNamespace())
		if ns != "" {
			return formulae.ScoreSBOMProfFull("namespace", false)
		}
		return formulae.ScoreSBOMProfMissingNA("namespace", false)

	case string(sbom.SBOMSpecCDX):
		uri := strings.TrimSpace(doc.Spec().GetURI())
		if uri != "" {
			return formulae.ScoreSBOMProfFull("namespace", false)
		}

		return formulae.ScoreSBOMProfMissingNA("namespace", false)
	}
	return formulae.ScoreSBOMProfNA(formulae.UnknownSpec(), true)
}

// SBOMAuthor represents an legal entity created an SBOM.
// SPDX: Creator.(Person/Organization); CDX: metadata.(authors/author)
func SBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	total := len(doc.Authors())

	if total == 0 {
		return formulae.ScoreSBOMProfMissingNA("authors", false)
	}

	return formulae.ScoreSBOMProfFull(fmt.Sprintf("%d authors", total), false)
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

// CompName: percentage of components that have a non-empty name.
// Package.Name for SPDX, Compnent.Name for CDX
func CompName(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		formulae.ScoreProfNA()
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
		formulae.ScoreProfNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "versions", false)
}

// CompWithLicenses check for concluded license
func CompLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
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

// CompWithSHA1Plus returns coverage of components that have SHA-1 or stronger
// (SHA-1, SHA-256, SHA-384, or SHA-512).
func CompHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
	}

	have := 0
	for _, comp := range comps {
		if hasAnySHA(comp) {
			have++
		}
	}

	return formulae.ScoreProfFull(have, len(comps), "SHA-1+", false)
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

// CompWithSHA256Plus returns coverage of components that have SHA-256 or stronger.
func CompSHA256Plus(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
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

// CompSourceCodeURL checks source code url
func CompSourceCodeURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetSourceCodeURL()) != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "source URIs", false)
}

// CompDownloadCodeURL checks download url
func CompDownloadCodeURL(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetDownloadLocationURL()) != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "download URIs", false)
}

// CompSourceCodeHash
func CompSourceCodeHash(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.SourceCodeHash() != ""
	})

	return formulae.ScoreProfFull(have, len(comps), "source code hash", false)
}

// CompDependencies checks for component level dependencies
// SPDX: relationships (DEPENDS_ON); CDX: component.dependencies / bom.dependencies
func CompDependencies(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
	}

	have := lo.CountBy(comps, func(c sbom.GetComponent) bool {
		return c.HasRelationShips() || c.CountOfDependencies() > 0
	})

	return formulae.ScoreProfFull(have, len(comps), "dependencies", false)
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

// CompDeclaredLicenses look for declared licenses
func CompDeclaredLicenses(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
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
		return catalog.ProfFeatScore{Score: 0.0, Desc: "vulnerabilities found: " + strings.Join(ids, ", "), Ignore: false}
	}

	return formulae.ScoreSBOMProfFull("no vulnerabilities", false)
}

func CompUniqID(doc sbom.Document) catalog.ProfFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreProfNA()
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return catalog.ProfFeatScore{
		Score:  formulae.PerComponentScore(len(have), len(comps)),
		Desc:   formulae.CompDescription(len(have), len(comps), "names"),
		Ignore: false,
	}
}
