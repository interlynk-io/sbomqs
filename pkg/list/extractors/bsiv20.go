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

// BSI v2.0 extractors mirror the logic in pkg/scorer/v2/profiles/bsiv20.go.
// Where a v2.0 function simply delegates to a v1.1 function the extractor
// reuses the corresponding BSIV21* extractor (which already mirrors the same
// v1.1 logic). Only extractors that differ from their v2.1 equivalents are
// defined here.
//
// Key differences from v2.1:
//   - sbom_uri: uses GetURI() only (no GetNamespace() fallback, matches BSIV11SBOMURI)
//   - comp_other_identifiers: PURLs + CPEs only; SWIDs added only in v2.1
//   - comp_associated_license: ConcludedLicenses preferred, DeclaredLicenses fallback
//   - comp_concluded_license: ConcludedLicenses only
//   - comp_declared_license: DeclaredLicenses only
//   - Property feature key suffix: "_property" (v2.0) vs "_prop" (v2.1) — handled in registry

package extractors

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// BSIV20SBOMURI checks the SBOM-URI field.
// CDX: serialNumber. SPDX: documentNamespace.
// v2.0 delegates to BSIV11SBOMURI which uses GetURI() only (no GetNamespace() fallback).
// Mirrors: profiles.BSIV20SBOMURI → profiles.BSIV11SBOMURI
func BSIV20SBOMURI(doc sbom.Document) (bool, string, error) {
	candidate := strings.TrimSpace(doc.Spec().GetURI())
	if candidate == "" {
		return false, "missing", nil
	}
	if !bsiIsValidURL(candidate) && !strings.HasPrefix(candidate, "urn:") {
		return false, fmt.Sprintf("present but invalid: %s", candidate), nil
	}
	return true, candidate, nil
}

// BSIV20CompAssociatedLicense extracts the associated licence for each component.
// Associated licences = what the licensee can use (SBOM-creator's perspective).
// ConcludedLicenses is the primary source; DeclaredLicenses is the fallback.
// Accepts valid SPDX IDs and LicenseRef-*; rejects NONE/NOASSERTION.
// Mirrors: profiles.BSIV20CompAssociatedLicenses → profiles.BSIV11CompLicenses
func BSIV20CompAssociatedLicense(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	// ConcludedLicenses (preferred)
	for _, l := range comp.ConcludedLicenses() {
		if l != nil && bsiIsAcceptableLicense(l) {
			return true, l.ShortID(), nil
		}
	}
	// DeclaredLicenses (fallback)
	for _, l := range comp.DeclaredLicenses() {
		if l != nil && bsiIsAcceptableLicense(l) {
			return true, l.ShortID(), nil
		}
	}
	return false, "missing", nil
}

// BSIV20CompConcludedLicense extracts concluded licences for each component.
// Concluded licences = what the licensee has chosen (additional field in v2.0).
// Accepts valid SPDX IDs and LicenseRef-*; rejects NONE/NOASSERTION.
// Mirrors: profiles.BSIV20CompConcludedLicenses
func BSIV20CompConcludedLicense(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var accepted []string
	for _, l := range comp.ConcludedLicenses() {
		if l != nil && bsiIsAcceptableLicense(l) {
			accepted = append(accepted, l.ShortID())
		}
	}
	if len(accepted) > 0 {
		return true, strings.Join(accepted, ", "), nil
	}
	return false, "missing", nil
}

// BSIV20CompDeclaredLicense extracts declared licences for each component.
// Declared licences = what the licensor stated (optional field in v2.0).
// Accepts valid SPDX IDs and LicenseRef-*; rejects NONE/NOASSERTION.
// Mirrors: profiles.BSIV20CompDeclaredLicenses
func BSIV20CompDeclaredLicense(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var accepted []string
	for _, l := range comp.DeclaredLicenses() {
		if l != nil && bsiIsAcceptableLicense(l) {
			accepted = append(accepted, l.ShortID())
		}
	}
	if len(accepted) > 0 {
		return true, strings.Join(accepted, ", "), nil
	}
	return false, "missing", nil
}

// BSIV20CompOtherIdentifiers extracts CPE and PURL identifiers.
// v2.0 lists CPE and PURL only; SWIDs were added in v2.1.
// Mirrors: profiles.BSIV20CompOtherIdentifiers → profiles.BSIV11CompOtherIdentifiers
func BSIV20CompOtherIdentifiers(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var all []string

	for _, p := range comp.GetPurls() {
		if s := strings.TrimSpace(string(p)); s != "" {
			all = append(all, s)
		}
	}
	for _, c := range comp.GetCpes() {
		if s := strings.TrimSpace(string(c)); s != "" {
			all = append(all, s)
		}
	}

	if len(all) > 0 {
		return true, strings.Join(all, ", "), nil
	}
	return false, "missing", nil
}
