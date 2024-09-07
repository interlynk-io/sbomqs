// Copyright 2023 Interlynk.io
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

package scvs

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

// 2.1 A structured, machine readable software bill of materials (SBOM) format is present(L1, L2, L3)
func IsSBOMMachineReadable(d sbom.Document, s *scvsScore) bool {
	// check spec is SPDX or CycloneDX
	specs := sbom.SupportedSBOMSpecs()

	for _, spec := range specs {
		if d.Spec().GetSpecType() == spec {
			s.setDesc("SBOM is machine readable")
			return true
		}
	}
	return false
}

// 2.3 SBOM creation is automated and reproducible(L2, L3)
func IsSBOMCreationAutomated(d sbom.Document, s *scvsScore) bool {
	noOfTools := len(d.Tools())
	if tools := d.Tools(); tools != nil {
		for _, tool := range tools {
			name := tool.GetName()
			version := tool.GetVersion()

			if name != "" && version != "" {
				s.setDesc(fmt.Sprintf("SBOM has %d authors", noOfTools))
				return true
			}
		}
	}

	s.setDesc(fmt.Sprintf("SBOM has %d authors", noOfTools))
	return false
}

// 2.3 Each SBOM has a unique identifier(L1, L2, L3)
func IsSBOMHasUniqID(d sbom.Document, s *scvsScore) bool {
	if ns := d.Spec().GetUniqID(); ns != "" {
		s.setDesc("SBOM has uniq ID")
		return true
	}
	s.setDesc("SBOM doesn't has uniq ID")
	return false
}

// 2.4 SBOM has been signed by publisher, supplier, or certifying authority(L2, L3)
func IsSBOMHasSignature(d sbom.Document, s *scvsScore) bool {
	// isSignatureExists := d.Spec().GetSignature().CheckSignatureExists()
	sig := d.Signature()

	if sig != nil {
		for _, signature := range sig {
			if signature != nil {
				return signature.CheckSignatureExists()
			}
		}
	} else {
		fmt.Println("Signature is nil")
	}

	return false
}

// 2.5  SBOM signature verification exists(L2, L3)
func IsSBOMSignatureCorrect(d sbom.Document, s *scvsScore) bool {
	return IsSBOMHasSignature(d, s)
}

// 2.6  SBOM signature verification is performed(L3)
func IsSBOMSignatureVerified(d sbom.Document, s *scvsScore) bool {
	// Save signature and public key to temporary files
	signature := d.Signature()
	if signature == nil {
		return false
	}

	// Use the first signature
	sig := signature[0]
	if sig == nil {
		return false
	}

	sigFile, err := os.CreateTemp("", "signature-*.sig")
	if err != nil {
		fmt.Println("Error creating temp file for signature:", err)
		return false
	}
	defer os.Remove(sigFile.Name())

	pubKeyFile, err := os.CreateTemp("", "publickey-*.pem")
	if err != nil {
		fmt.Println("Error creating temp file for public key:", err)
		return false
	}
	defer os.Remove(pubKeyFile.Name())

	_, err = sigFile.WriteString(sig.Value())
	if err != nil {
		fmt.Println("Error writing signature to temp file:", err)
		return false
	}
	_, err = pubKeyFile.WriteString(sig.PublicKey())
	if err != nil {
		fmt.Println("Error writing public key to temp file:", err)
		return false
	}

	// Use openssl to verify the signature
	cmd := exec.Command("openssl", "dgst", "-verify", pubKeyFile.Name(), "-signature", sigFile.Name(), "data-to-verify.txt")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error verifying signature with openssl:", err)
		return false
	}

	verificationResult := strings.Contains(string(output), "Verified OK")
	fmt.Println("Verification result:", verificationResult)

	return verificationResult
}

// 2.7 SBOM is timestamped(L1, L2, L3)
func IsSBOMTimestamped(d sbom.Document, s *scvsScore) bool {
	if result := d.Spec().GetCreationTimestamp(); result != "" {
		_, err := time.Parse(time.RFC3339, result)
		if err != nil {
			s.setDesc("SBOM timestamped is incorrect")
			return false
		}
		s.setDesc("SBOM is timestamped")
		return true
	}
	s.setDesc("SBOM isn't timestamped")
	return false
}

// 2.8 SBOM is analyzed for risk(L1, L2, L3)
func IsSBOMAnalyzedForRisk(d sbom.Document, s *scvsScore) bool { return false } // 2.8

// 2.9 SBOM contains a complete and accurate inventory of all components the SBOM describes(L1, L2, L3)
func IsSBOMHasInventoryOfDependencies(d sbom.Document, s *scvsScore) bool {
	// get primaryComponentID: d.PrimaryComponent().GetID()
	// get all dependencies of primary component: loop through all relation and collect all dependencies of primary comp
	// now check each dependencies are present in component section: now through each component and check depedncies aare present or not.
	return false
}

// 2,10 SBOM contains an accurate inventory of all test components for the asset or application it describes(L2, L3)
func IsSBOMInventoryContainsTestComponents(_ sbom.Document, s *scvsScore) bool {
	// N/A
	s.setDesc("Not Supported(N/A)")
	return false
}

// 2.11 SBOM contains metadata about the asset or software the SBOM describes(L2, L3)
func IsSBOMHasPrimaryComponents(d sbom.Document, s *scvsScore) bool {
	// get primaryComponentID: d.PrimaryComponent().GetID()
	// Update this after NTIA get's merged
	if d.PrimaryComponent() {
		s.setDesc("SBOM have primary comp")
		return true
	}
	s.setDesc("SBOM doesn't have primary comp")
	return false
}

// 2.12 Component identifiers are derived from their native ecosystems (if applicable)(L1, L2, L3)
func IsComponentHasIdentityID(d sbom.Document, s *scvsScore) bool {
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setDesc("N/A (no components)")
		return false
	}

	withIdentityID := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.Purls()) > 0 || len(c.Cpes()) > 0
	})

	if totalComponents > 0 {
		if withIdentityID == totalComponents {
			s.setDesc(fmt.Sprintf("%d/%d comp have Identity ID's", withIdentityID, totalComponents))
			return true
		}
	}
	s.setDesc(fmt.Sprintf("%d/%d comp have Identity ID's", withIdentityID, totalComponents))
	return false
}

// 2.13 Component point of origin is identified in a consistent, machine readable format (e.g. PURL)(L3)
func IsComponentHasOriginID(d sbom.Document, s *scvsScore) bool {
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setDesc("N/A (no components)")
		return false
	}

	withOriginID := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.Purls()) > 0
	})

	if totalComponents > 0 {
		if withOriginID == totalComponents {
			s.setDesc(fmt.Sprintf("%d/%d comp have Origin ID's", withOriginID, totalComponents))
			return true
		}
	}
	s.setDesc(fmt.Sprintf("%d/%d comp have Origin ID's", withOriginID, totalComponents))
	return false
}

// 2.14 Components defined in SBOM have accurate license information(L1, L2, L3)
func IsComponentHasLicenses(d sbom.Document, s *scvsScore) bool {
	//
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setDesc("N/A (no components)")
		return false
	}

	withLicenses := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.Licenses()) > 0
	})

	if totalComponents > 0 {
		if withLicenses >= totalComponents {
			s.setDesc(fmt.Sprintf("%d/%d comp has Licenses", withLicenses, totalComponents))
			return true
		}
	}
	s.setDesc(fmt.Sprintf("%d/%d comp has Licenses", withLicenses, totalComponents))
	return false
}

// 2.15 Components defined in SBOM have valid SPDX license ID's or expressions (if applicable)(L2, L3)
func IsComponentHasVerifiedLicense(d sbom.Document, s *scvsScore) bool {
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setDesc("N/A (no components)")
		return false
	}

	totalLicense := lo.FlatMap(d.Components(), func(comp sbom.GetComponent, _ int) []bool {
		return lo.Map(comp.Licenses(), func(l licenses.License, _ int) bool {
			isValidLicense := licenses.IsValidLicenseID(l.ShortID())
			fmt.Println("isValidLicense: ", isValidLicense)
			return isValidLicense
		})
	})

	withValidLicense := lo.CountBy(totalLicense, func(l bool) bool {
		return l
	})

	if totalComponents >= 0 {
		if withValidLicense >= totalComponents {
			s.setDesc(fmt.Sprintf("%d/%d comp has Licenses", withValidLicense, totalComponents))
			return true
		}
	}

	s.setDesc(fmt.Sprintf("%d/%d comp has valid Licenses", withValidLicense, totalComponents))
	return false
}

// 2.16 Components defined in SBOM have valid copyright statement(L3)
func IsComponentHasCopyright(d sbom.Document, s *scvsScore) bool {
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setDesc("N/A (no components)")
		return false
	}

	withCopyrights := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetCopyRight()) > 0
	})

	if totalComponents > 0 {
		if withCopyrights == totalComponents {
			s.setDesc(fmt.Sprintf("%d/%d comp has Copyright", withCopyrights, totalComponents))
			return true
		}
	}
	s.setDesc(fmt.Sprintf("%d/%d comp has Copyright", withCopyrights, totalComponents))
	return false
}

// 2.17 Components defined in SBOM which have been modified from the original have detailed provenance and pedigree information(L3)
func IsComponentContainsModificationChanges(d sbom.Document, s *scvsScore) bool { return false } // 2.17

// 2.18 Components defined in SBOM have one or more file hashes (SHA-256, SHA-512, etc)(L3)
func IsComponentContainsHash(d sbom.Document, s *scvsScore) bool {
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		return false
	}

	withChecksums := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.GetChecksums()) > 0
	})
	if totalComponents > 0 {
		if withChecksums == totalComponents {
			s.setDesc(fmt.Sprintf("%d/%d comp has Checksum", withChecksums, totalComponents))
			return true
		}
	}
	s.setDesc(fmt.Sprintf("%d/%d comp has Checksum", withChecksums, totalComponents))
	return false
}
