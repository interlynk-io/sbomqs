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

// Package common provides shared helper functions used across sbomqs checks.
// It focuses on simple yes/no style questions about an SBOM: does it have a
// real supplier or author, valid PURLs or CPEs, meaningful licenses, or strong
// checksums. Higher-level scoring and compliance code builds on these helpers
// instead of re-implementing the validation logic.
package common

import (
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	purl "github.com/package-url/packageurl-go"

	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// isSupplierEntity check whether supplier is a legal entity or not:
// supplier should have either name/email info.
// these info represents a legal entity
func IsSupplierEntity(supplier sbom.GetSupplier) bool {
	if supplier.GetName() != "" || supplier.GetEmail() != "" {
		return true
	}
	return false
}

// isSBOMAuthorEntity check whether author is a legal entity or not:
// author should have name + email/phone info.
func IsSBOMAuthorEntity(doc sbom.Document) bool {
	for _, author := range doc.Authors() {
		if strings.TrimSpace(author.GetName()) != "" || strings.TrimSpace(author.GetEmail()) != "" || strings.TrimSpace(author.GetPhone()) != "" {
			return true
		}
	}
	return false
}

func HasComponentSourceCodeURL(sourceCodeURL string) bool {
	if strings.TrimSpace(sourceCodeURL) != "" {
		return true
	}
	return false
}

func HasSBOMPrimaryComponent(doc sbom.Document) bool {
	return doc.PrimaryComp().IsPresent()
}

func HasComponentDependencies(c sbom.GetComponent) bool {
	return c.HasRelationShips() || c.CountOfDependencies() > 0
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

func CompHasAnyPURLs(c sbom.GetComponent) bool {

	for _, p := range c.GetPurls() {
		if isValidPURL(string(p)) {
			return true
		}
	}

	return false
}

func CompHasAnyCPEs(c sbom.GetComponent) bool {

	for _, p := range c.GetCpes() {
		if isValidCPE(string(p)) {
			return true
		}
	}

	return false
}

// func CompHasAnySWID(c sbom.GetComponent) bool {

// 	for _, p := range c.GetSWIDs() {
// 		if IsValidSWIDs(string(p)) {
// 			return true
// 		}
// 	}

// 	return false
// }

// license with "NOASSERTION" or "NONE" are considered as
// non-meaningful licenses
func ValidateLicenseText(s string) bool {
	if s == "" {
		return false
	}

	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "NOASSERTION" || u == "NONE" {
		return false
	}
	return true
}

func ValidationCheckConcludedLicenses(c sbom.GetComponent) bool {
	lics := c.ConcludedLicenses()
	if len(lics) == 0 {
		return false
	}

	return AreLicensesValid(lics)
}

func AreLicensesValid(licenses []licenses.License) bool {
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

func ComponentHasAnyConcluded(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if id := strings.TrimSpace(l.ShortID()); ValidateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); ValidateLicenseText(nm) {
			return true
		}
	}
	return false
}

func ComponentHasAnyDeclared(c sbom.GetComponent) bool {
	for _, l := range c.DeclaredLicenses() {
		if id := strings.TrimSpace(l.ShortID()); ValidateLicenseText(id) {
			return true
		}
		if nm := strings.TrimSpace(l.Name()); ValidateLicenseText(nm) {
			return true
		}
	}
	return false
}

func ComponentHasAnyDeprecated(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Deprecated() {
			return true
		}
	}
	return false
}

func ComponentHasAnyRestrictive(c sbom.GetComponent) bool {
	for _, l := range c.ConcludedLicenses() {
		if l.Restrictive() {
			return true
		}
	}
	return false
}

// HasAnyChecksum checks whether a component declares any cryptographic hash
// (weak or strong). This represents the FSCT baseline expectation.
func HasAnyChecksum(c sbom.GetComponent) bool {
	for _, checksum := range c.GetChecksums() {
		algo := NormalizeAlgoName(checksum.GetAlgo())
		content := strings.TrimSpace(checksum.GetContent())

		if content == "" {
			continue
		}

		// FSCT allows both weak and strong hashes at baseline
		if IsWeakChecksum(algo) || IsStrongChecksum(algo) {
			return true
		}
	}
	return false
}

// HasStrongChecksum checks if the component declares at least one
// cryptographically strong hash algorithm.
// (Not required by FSCT baseline; useful for maturity/quality signals.)
func HasStrongChecksum(c sbom.GetComponent) bool {
	for _, checksum := range c.GetChecksums() {
		algo := NormalizeAlgoName(checksum.GetAlgo())
		if IsStrongChecksum(algo) && strings.TrimSpace(checksum.GetContent()) != "" {
			return true
		}
	}
	return false
}

// HasWeakChecksum checks if the component declares only weak hash algorithms
// (i.e., no strong hashes present).
func HasWeakChecksum(c sbom.GetComponent) bool {
	hasWeak := false

	for _, checksum := range c.GetChecksums() {
		algo := NormalizeAlgoName(checksum.GetAlgo())
		content := strings.TrimSpace(checksum.GetContent())

		if content == "" {
			continue
		}

		if IsStrongChecksum(algo) {
			return false // Has strong, so not "weak only"
		}

		if IsWeakChecksum(algo) {
			hasWeak = true
		}
	}

	return hasWeak
}

// isWeakChecksum returns true for weak/broken hash algorithms.
// Weak algorithms (no credit):
//   - MD family: MD2, MD4, MD5, MD6
//   - SHA-1
//   - Adler-32 (non-cryptographic)
func IsWeakChecksum(algo string) bool {
	switch algo {
	case "MD2", "MD4", "MD5", "MD6":
		return true
	case "SHA1":
		return true
	case "ADLER32":
		return true
	default:
		return false
	}
}

// isStrongChecksum returns true for strong hash algorithms.
// Strong algorithms (full credit):
//   - SHA-2 family: SHA-224, SHA-256, SHA-384, SHA-512
//   - SHA-3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512
//   - BLAKE family: BLAKE2b-256, BLAKE2b-384, BLAKE2b-512, BLAKE3
//   - Streebog family: Streebog-256, Streebog-512
//   - Post-quantum: crystalsDilithium, crystalsKyber, falcon
func IsStrongChecksum(algo string) bool {
	switch algo {
	// SHA-2 family (SHA-224 and above)
	case "SHA224", "SHA256", "SHA384", "SHA512":
		return true
	// SHA-3 family
	case "SHA3224", "SHA3256", "SHA3384", "SHA3512":
		return true
	// BLAKE family
	case "BLAKE2B256", "BLAKE2B384", "BLAKE2B512", "BLAKE3":
		return true
	// Streebog (GOST R 34.11-2012)
	case "STREEBOG256", "STREEBOG512":
		return true
	// Post-quantum algorithms
	case "CRYSTALSDILITHIUM", "CRYSTALSKYBER", "FALCON":
		return true
	default:
		return false
	}
}

// HasSHA1Plus checks if component has any recognized checksum (weak or strong).
// Kept for backward compatibility.
func HasSHA1Plus(c sbom.GetComponent) bool {
	return HasAnyChecksum(c)
}

// HasSHA256Plus checks if component has a strong hash algorithm.
// Kept for backward compatibility.
func HasSHA256Plus(c sbom.GetComponent) bool {
	return HasStrongChecksum(c)
}

// normalizeAlgoName normalizes algorithm names for comparison.
// Handles variations from both CycloneDX and SPDX specs:
//   - CycloneDX: "SHA-256", "SHA3-256", "BLAKE2b-256", "Streebog-256"
//   - SPDX: "SHA256", "SHA3_256", "BLAKE2b-256"
//
// After normalization, "SHA-256", "SHA256", "sha_256" all become "SHA256"
func NormalizeAlgoName(algo string) string {
	n := strings.ToUpper(algo)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	n = strings.TrimSpace(n)
	return n
}
