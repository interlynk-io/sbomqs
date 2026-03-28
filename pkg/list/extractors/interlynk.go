// Copyright 2026 Interlynk.io
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

// Interlynk profile extractors mirror the logic in
// pkg/scorer/v2/profiles/interlynk.go and pkg/scorer/v2/profiles/common.go
// but return the actual field value for display instead of a score.
//
// Feature keys (from pkg/scorer/v2/registry/registry.go InterlynkKeyToEvaluatingFunction):
//
//   Identification:
//     comp_name        → BSIV21CompName (reused)
//     comp_version     → BSIV21CompVersion (reused)
//     comp_local_id    → InterlynkCompLocalID (PURL or CPE)
//
//   Provenance:
//     sbom_timestamp   → BSIV21SBOMTimestamp (reused)
//     sbom_authors     → InterlynkSBOMAuthors
//     sbom_tool        → InterlynkSBOMTool
//     sbom_supplier    → InterlynkSBOMSupplier
//     sbom_namespace   → InterlynkSBOMNamespace
//     sbom_lifecycle   → InterlynkSBOMLifecycle
//
//   Integrity:
//     comp_checksums   → InterlynkCompChecksums (any checksum, SHA-1+)
//     comp_sha256      → InterlynkCompSHA256 (SHA-256+)
//     sbom_signature   → InterlynkSBOMSignature
//
//   Completeness:
//     comp_dependencies     → InterlynkCompDependencies
//     sbom_completeness     → InterlynkSBOMCompleteness
//     sbom_primary_component → InterlynkSBOMPrimaryComponent
//     comp_source_code      → InterlynkCompSourceCode
//     comp_supplier         → InterlynkCompSupplier
//     comp_purpose          → InterlynkCompPurpose
//
//   Licensing:
//     comp_licenses              → InterlynkCompLicenses
//     comp_valid_licenses        → InterlynkCompValidLicenses
//     comp_no_deprecated_licenses → InterlynkCompNoDeprecatedLicenses
//     comp_no_restrictive_licenses → InterlynkCompNoRestrictiveLicenses
//     comp_declared_licenses     → InterlynkCompDeclaredLicenses
//     sbom_data_license          → InterlynkSBOMDataLicense
//
//   Vulnerability:
//     comp_purl → InterlynkCompPURL
//     comp_cpe  → InterlynkCompCPE
//
//   Structural:
//     sbom_spec_declared → InterlynkSBOMSpecDeclared
//     sbom_spec_version  → InterlynkSBOMSpecVersion
//     sbom_file_format   → InterlynkSBOMFileFormat
//     sbom_schema_valid  → InterlynkSBOMSchemaValid

package extractors

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	scorercommon "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
)

// ============================================================
// Interlynk — Identification (component-level)
// ============================================================

// InterlynkCompLocalID reports the first PURL or CPE found for the component.
// Mirrors: profiles.InterCompWithUniqueID → profiles.CompUniqID
func InterlynkCompLocalID(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	// Try PURLs first
	for _, p := range comp.GetPurls() {
		s := strings.TrimSpace(string(p))
		if s != "" {
			return true, fmt.Sprintf("purl: %s", s), nil
		}
	}
	// Fallback: CPEs
	for _, c := range comp.GetCpes() {
		s := strings.TrimSpace(string(c))
		if s != "" {
			return true, fmt.Sprintf("cpe: %s", s), nil
		}
	}
	return false, "missing", nil
}

// ============================================================
// Interlynk — Provenance (SBOM-level)
// ============================================================

// InterlynkSBOMAuthors reports the SBOM's author identities.
// Requires at least one author with a non-empty name, email, or phone.
// Mirrors: profiles.InterSBOMAuthors → profiles.SBOMAuthors
func InterlynkSBOMAuthors(doc sbom.Document) (bool, string, error) {
	var parts []string
	for _, a := range doc.Authors() {
		if a == nil {
			continue
		}
		name := strings.TrimSpace(a.GetName())
		email := strings.TrimSpace(a.GetEmail())
		if name != "" && email != "" {
			parts = append(parts, fmt.Sprintf("%s <%s>", name, email))
		} else if name != "" {
			parts = append(parts, name)
		} else if email != "" {
			parts = append(parts, email)
		}
	}
	if len(parts) > 0 {
		return true, strings.Join(parts, "; "), nil
	}
	return false, "missing", nil
}

// InterlynkSBOMTool reports tools with both name and version declared.
// Mirrors: profiles.InterSBOMTOol → profiles.SBOMTool
func InterlynkSBOMTool(doc sbom.Document) (bool, string, error) {
	var toolsWithNV []string
	for _, t := range doc.Tools() {
		name := strings.TrimSpace(t.GetName())
		ver := strings.TrimSpace(t.GetVersion())
		if name != "" && ver != "" {
			toolsWithNV = append(toolsWithNV, name+"-"+ver)
		}
	}
	if len(toolsWithNV) > 0 {
		return true, strings.Join(toolsWithNV, ", "), nil
	}
	return false, "missing", nil
}

// InterlynkSBOMSupplier reports the SBOM-level supplier.
// CDX: metadata.supplier — requires both name and a contact (email or URL).
// SPDX: not supported at document level.
// Mirrors: profiles.InterSBOMSupplier → profiles.SBOMSupplier
func InterlynkSBOMSupplier(doc sbom.Document) (bool, string, error) {
	spec := strings.ToLower(strings.TrimSpace(doc.Spec().GetSpecType()))
	if spec == strings.ToLower(string(sbom.SBOMSpecSPDX)) {
		return false, "not supported in SPDX", nil
	}
	s := doc.Supplier()
	if s != nil {
		name := strings.TrimSpace(s.GetName())
		email := strings.TrimSpace(s.GetEmail())
		url := strings.TrimSpace(s.GetURL())
		if name != "" && (email != "" || url != "") {
			contact := email
			if contact == "" {
				contact = url
			}
			return true, fmt.Sprintf("%s (%s)", name, contact), nil
		}
	}
	return false, "missing", nil
}

// InterlynkSBOMNamespace reports the SBOM URI or namespace.
// SPDX: documentNamespace. CDX: serialNumber.
// Mirrors: profiles.InterSBOMNamespace → profiles.SBOMNamespace
func InterlynkSBOMNamespace(doc sbom.Document) (bool, string, error) {
	uri := strings.TrimSpace(doc.Spec().GetURI())
	if uri == "" {
		uri = strings.TrimSpace(doc.Spec().GetNamespace())
	}
	if uri != "" {
		return true, uri, nil
	}
	return false, "missing", nil
}

// InterlynkSBOMLifecycle reports the declared lifecycle phase(s) of the SBOM.
// CDX only — SPDX does not have a lifecycle field.
// Mirrors: profiles.InterSBOMLifecycle → profiles.SBOMLifeCycle
func InterlynkSBOMLifecycle(doc sbom.Document) (bool, string, error) {
	spec := strings.ToLower(strings.TrimSpace(doc.Spec().GetSpecType()))
	if spec == strings.ToLower(string(sbom.SBOMSpecSPDX)) {
		return false, "not supported in SPDX", nil
	}
	var phases []string
	for _, p := range doc.Lifecycles() {
		if strings.TrimSpace(p) != "" {
			phases = append(phases, p)
		}
	}
	if len(phases) > 0 {
		return true, strings.Join(phases, ", "), nil
	}
	return false, "missing", nil
}

// ============================================================
// Interlynk — Integrity
// ============================================================

// InterlynkCompChecksums reports the first recognized checksum (SHA-1 or stronger).
// Mirrors: profiles.InterCompWithChecksum → profiles.CompHashSHA1Plus → common.HasSHA1Plus
func InterlynkCompChecksums(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	for _, cs := range comp.GetChecksums() {
		algo := scorercommon.NormalizeAlgoName(cs.GetAlgo())
		content := strings.TrimSpace(cs.GetContent())
		if content == "" {
			continue
		}
		if scorercommon.IsWeakChecksum(algo) || scorercommon.IsStrongChecksum(algo) {
			return true, fmt.Sprintf("%s:%s", algo, content), nil
		}
	}
	return false, "missing", nil
}

// InterlynkCompSHA256 reports the first strong checksum (SHA-256 or stronger).
// Mirrors: profiles.InterCompWithChecksum265 → profiles.CompSHA256Plus → common.HasSHA256Plus
func InterlynkCompSHA256(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	for _, cs := range comp.GetChecksums() {
		algo := scorercommon.NormalizeAlgoName(cs.GetAlgo())
		content := strings.TrimSpace(cs.GetContent())
		if content == "" {
			continue
		}
		if scorercommon.IsStrongChecksum(algo) {
			return true, fmt.Sprintf("%s:%s", algo, content), nil
		}
	}
	return false, "missing", nil
}

// InterlynkSBOMSignature reports the SBOM signature metadata.
// CDX only — SPDX does not support signatures.
// Mirrors: profiles.InterSBOMSignature → profiles.SBOMSignature
func InterlynkSBOMSignature(doc sbom.Document) (bool, string, error) {
	spec := strings.ToLower(strings.TrimSpace(doc.Spec().GetSpecType()))
	if spec == strings.ToLower(string(sbom.SBOMSpecSPDX)) {
		return false, "not supported in SPDX", nil
	}
	sig := doc.Signature()
	if sig == nil {
		return false, "missing", nil
	}
	algorithm := strings.TrimSpace(sig.GetAlgorithm())
	sigValue := strings.TrimSpace(sig.GetSigValue())
	if algorithm == "" || sigValue == "" {
		return false, "incomplete signature", nil
	}
	pubKey := strings.TrimSpace(sig.GetPublicKey())
	certPaths := sig.GetCertificatePath()
	if pubKey != "" || len(certPaths) > 0 {
		return true, fmt.Sprintf("algorithm: %s (with verification material)", algorithm), nil
	}
	return true, fmt.Sprintf("algorithm: %s (no verification key)", algorithm), nil
}

// ============================================================
// Interlynk — Completeness (component-level)
// ============================================================

// InterlynkCompDependencies reports whether the component declares dependencies.
// Mirrors: profiles.InterCompWithDependencies (checks primary comp deps)
// At component level: checks HasRelationShips or CountOfDependencies.
func InterlynkCompDependencies(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	if comp.HasRelationShips() {
		return true, fmt.Sprintf("%d relationships", comp.CountOfDependencies()), nil
	}
	if comp.CountOfDependencies() > 0 {
		return true, fmt.Sprintf("%d dependencies", comp.CountOfDependencies()), nil
	}
	return false, "missing", nil
}

// InterlynkCompSourceCode reports the component source code URL.
// SPDX: PackageSourceInfo. CDX: externalReference type=vcs.
// Mirrors: profiles.InterCompWithSourceCode → profiles.CompSourceCodeURL
func InterlynkCompSourceCode(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	url := strings.TrimSpace(comp.GetSourceCodeURL())
	if url != "" {
		return true, url, nil
	}
	return false, "missing", nil
}

// InterlynkCompSupplier reports the component supplier name.
// Supplier must have a name or email (IsSupplierEntity).
// Mirrors: profiles.InterCompWithSupplier → profiles.CompSupplier
func InterlynkCompSupplier(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	s := comp.Suppliers()
	if !s.IsAbsent() {
		name := strings.TrimSpace(s.GetName())
		email := strings.TrimSpace(s.GetEmail())
		if name != "" || email != "" {
			if name != "" && email != "" {
				return true, fmt.Sprintf("%s <%s>", name, email), nil
			}
			if name != "" {
				return true, name, nil
			}
			return true, email, nil
		}
	}
	return false, "missing", nil
}

// InterlynkCompPurpose reports the component's primary purpose if it is a recognized type.
// Mirrors: profiles.InterCompWithPurpose → profiles.CompPurpose
func InterlynkCompPurpose(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	purpose := strings.TrimSpace(comp.PrimaryPurpose())
	if purpose == "" {
		return false, "missing", nil
	}
	supported := sbom.SupportedPrimaryPurpose(doc.Spec().GetSpecType())
	purposeLower := strings.ToLower(purpose)
	for _, s := range supported {
		if purposeLower == s {
			return true, purpose, nil
		}
	}
	return false, fmt.Sprintf("unrecognized purpose: %s", purpose), nil
}

// ============================================================
// Interlynk — Completeness (SBOM-level)
// ============================================================

// InterlynkSBOMCompleteness reports the SBOM's composition completeness declaration.
// CDX: compositions/aggregate. SPDX: not supported.
// Mirrors: profiles.InterSBOMCompleteness → profiles.SBOMCompleteness
func InterlynkSBOMCompleteness(doc sbom.Document) (bool, string, error) {
	spec := strings.ToLower(strings.TrimSpace(doc.Spec().GetSpecType()))
	if spec == strings.ToLower(string(sbom.SBOMSpecSPDX)) {
		return false, "not supported in SPDX", nil
	}
	// CDX: completeness is tracked via composition entries
	// profiles.SBOMCompleteness currently marks this as not implemented
	return false, "completeness not implemented for CDX (no composition aggregate field)", nil
}

// InterlynkSBOMPrimaryComponent reports whether the SBOM has a primary component declared.
// Mirrors: profiles.InterSBOMPrimaryComponent → profiles.SBOMPrimaryComponent
func InterlynkSBOMPrimaryComponent(doc sbom.Document) (bool, string, error) {
	pc := doc.PrimaryComp()
	if pc.IsPresent() {
		name := strings.TrimSpace(pc.GetName())
		version := strings.TrimSpace(pc.GetVersion())
		if name != "" && version != "" {
			return true, fmt.Sprintf("%s@%s", name, version), nil
		}
		if name != "" {
			return true, name, nil
		}
		return true, pc.GetID(), nil
	}
	return false, "missing", nil
}

// ============================================================
// Interlynk — Licensing (component-level)
// ============================================================

// InterlynkCompLicenses reports concluded licenses for the component.
// Mirrors: profiles.InterCompWithLicenses → profiles.CompLicenses → common.ComponentHasAnyConcluded
func InterlynkCompLicenses(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var found []string
	for _, l := range comp.ConcludedLicenses() {
		if l == nil {
			continue
		}
		id := strings.TrimSpace(l.ShortID())
		if scorercommon.ValidateLicenseText(id) {
			found = append(found, id)
		}
	}
	if len(found) > 0 {
		return true, strings.Join(found, ", "), nil
	}
	return false, "missing", nil
}

// InterlynkCompValidLicenses reports concluded licenses, same as InterlynkCompLicenses.
// Both InterCompWithLicenses and InterCompWithValidLicenses delegate to CompLicenses.
// Mirrors: profiles.InterCompWithValidLicenses → profiles.CompLicenses
func InterlynkCompValidLicenses(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return InterlynkCompLicenses(doc, comp)
}

// InterlynkCompNoDeprecatedLicenses reports deprecated concluded licenses.
// Returns true if NO deprecated licenses are found (the "good" case).
// Mirrors: profiles.InterCompWithNODeprecatedLicenses → profiles.CompWithNODeprecatedLicenses
func InterlynkCompNoDeprecatedLicenses(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var deprecated []string
	for _, l := range comp.ConcludedLicenses() {
		if l != nil && l.Deprecated() {
			deprecated = append(deprecated, l.ShortID())
		}
	}
	if len(deprecated) == 0 {
		return true, "no deprecated licenses", nil
	}
	return false, fmt.Sprintf("%d deprecated: %s", len(deprecated), strings.Join(deprecated, ", ")), nil
}

// InterlynkCompNoRestrictiveLicenses reports restrictive concluded licenses.
// Returns true if NO restrictive licenses are found (the "good" case).
// Mirrors: profiles.InterCompWithNORestrictiveLicenses → profiles.CompWithNORestrictiveLicenses
func InterlynkCompNoRestrictiveLicenses(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var restrictive []string
	for _, l := range comp.ConcludedLicenses() {
		if l != nil && l.Restrictive() {
			restrictive = append(restrictive, l.ShortID())
		}
	}
	if len(restrictive) == 0 {
		return true, "no restrictive licenses", nil
	}
	return false, fmt.Sprintf("%d restrictive: %s", len(restrictive), strings.Join(restrictive, ", ")), nil
}

// InterlynkCompDeclaredLicenses reports declared (original) licenses for the component.
// Mirrors: profiles.InterCompWithDeclaredLicenses → profiles.CompDeclaredLicenses → common.ComponentHasAnyDeclared
func InterlynkCompDeclaredLicenses(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var found []string
	for _, l := range comp.DeclaredLicenses() {
		if l == nil {
			continue
		}
		id := strings.TrimSpace(l.ShortID())
		if scorercommon.ValidateLicenseText(id) {
			found = append(found, id)
		}
	}
	if len(found) > 0 {
		return true, strings.Join(found, ", "), nil
	}
	return false, "missing", nil
}

// ============================================================
// Interlynk — Licensing (SBOM-level)
// ============================================================

// InterlynkSBOMDataLicense reports the SBOM's data license.
// Uses SPDX spec licenses (valid SPDX/aboutcode/LicenseRef-* IDs).
// Mirrors: profiles.InterSBOMDataLicenses → profiles.SBOMDataLicense
func InterlynkSBOMDataLicense(doc sbom.Document) (bool, string, error) {
	lics := doc.Spec().GetLicenses()
	if len(lics) == 0 {
		return false, "missing", nil
	}
	var ids []string
	for _, l := range lics {
		if l != nil {
			ids = append(ids, l.ShortID())
		}
	}
	if scorercommon.AreLicensesValid(lics) {
		return true, strings.Join(ids, ", "), nil
	}
	return false, fmt.Sprintf("invalid data license: %s", strings.Join(ids, ", ")), nil
}

// ============================================================
// Interlynk — Vulnerability (component-level)
// ============================================================

// InterlynkCompPURL reports all valid PURLs for the component.
// Mirrors: profiles.InterCompWithPURL → profiles.CompPURL → common.CompHasAnyPURLs
func InterlynkCompPURL(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var valid []string
	for _, p := range comp.GetPurls() {
		s := strings.TrimSpace(string(p))
		if s != "" {
			valid = append(valid, s)
		}
	}
	if len(valid) > 0 {
		return true, strings.Join(valid, ", "), nil
	}
	return false, "missing", nil
}

// InterlynkCompCPE reports all valid CPEs for the component.
// Mirrors: profiles.InterCompWithCPE → profiles.CompCPE → common.CompHasAnyCPEs
func InterlynkCompCPE(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var valid []string
	for _, c := range comp.GetCpes() {
		s := strings.TrimSpace(string(c))
		if s != "" {
			valid = append(valid, s)
		}
	}
	if len(valid) > 0 {
		return true, strings.Join(valid, ", "), nil
	}
	return false, "missing", nil
}

// ============================================================
// Interlynk — Structural (SBOM-level)
// ============================================================

// InterlynkSBOMSpecDeclared reports the SBOM specification type (SPDX or CycloneDX).
// Mirrors: profiles.InterSBOMSpec → profiles.SBOMSpec
func InterlynkSBOMSpecDeclared(doc sbom.Document) (bool, string, error) {
	spec := strings.TrimSpace(doc.Spec().GetSpecType())
	if spec == "" {
		return false, "missing", nil
	}
	specLower := strings.ToLower(spec)
	for _, s := range sbom.SupportedSBOMSpecs() {
		if specLower == strings.ToLower(s) {
			return true, spec, nil
		}
	}
	return false, fmt.Sprintf("unsupported spec: %s", spec), nil
}

// InterlynkSBOMSpecVersion reports the SBOM spec version.
// Mirrors: profiles.InterSBOMSpecVersion → profiles.SBOMSpecVersion
func InterlynkSBOMSpecVersion(doc sbom.Document) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())
	if ver == "" {
		return false, "missing", nil
	}
	supported := sbom.SupportedSBOMSpecVersions(spec)
	for _, v := range supported {
		if ver == v {
			return true, ver, nil
		}
	}
	return false, fmt.Sprintf("%s (unsupported for %s)", ver, spec), nil
}

// InterlynkSBOMFileFormat reports the SBOM file format.
// Mirrors: profiles.InterSBOMFileFormat → profiles.SBOMAutomationSpec
func InterlynkSBOMFileFormat(doc sbom.Document) (bool, string, error) {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	format := strings.TrimSpace(strings.ToLower(doc.Spec().FileFormat()))
	if format == "" {
		return false, "missing", nil
	}
	supported := sbom.SupportedSBOMFileFormats(spec)
	for _, f := range supported {
		if format == strings.ToLower(f) {
			return true, format, nil
		}
	}
	return false, fmt.Sprintf("unsupported format: %s", format), nil
}

// InterlynkSBOMSchemaValid reports whether the SBOM passes schema validation.
// Mirrors: profiles.InterSBOMSchema → profiles.SBOMSchema
func InterlynkSBOMSchemaValid(doc sbom.Document) (bool, string, error) {
	if doc.SchemaValidation() {
		return true, "valid", nil
	}
	return false, "invalid schema", nil
}

