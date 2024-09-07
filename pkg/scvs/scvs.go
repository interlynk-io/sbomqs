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

	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

// A structured, machine readable software bill of materials (SBOM) format is present
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

// SBOM creation is automated and reproducible
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

// 2.3 Each SBOM has a unique identifier
func IsSBOMHasUniqID(d sbom.Document, s *scvsScore) bool {
	if ns := d.Spec().GetUniqID(); ns != "" {
		s.setDesc("SBOM has uniq ID")
		return true
	}
	s.setDesc("SBOM doesn't has uniq ID")
	return false
}

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

func IsSBOMSignatureCorrect(d sbom.Document, s *scvsScore) bool {
	return IsSBOMHasSignature(d, s)
}

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

func IsSBOMTimestamped(d sbom.Document, s *scvsScore) bool {
	if d.Spec().GetCreationTimestamp() != "" {
		s.setDesc("SBOM is timestamped")
		return true
	}
	s.setDesc("SBOM isn't timestamped")
	return false
}

func IsSBOMAnalyzedForRisk(d sbom.Document, s *scvsScore) bool { return false } // 2.8

func IsSBOMHasInventoryOfDependencies(d sbom.Document, s *scvsScore) bool { return false } // 2.9

func IsSBOMInventoryContainsTestComponents(d sbom.Document, s *scvsScore) bool { return false } // 2.10

func IsSBOMHasPrimaryComponents(d sbom.Document, s *scvsScore) bool {
	//
	if d.PrimaryComponent() {
		s.setDesc("SBOM have primary comp")
		return true
	}
	s.setDesc("SBOM doesn't have primary comp")
	return false
}

func IsComponentHasIdentityID(d sbom.Document, s *scvsScore) bool {
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setDesc("N/A (no components)")
		return false
	}

	withIdentityID := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return len(c.Purls()) > 0
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

// 2.13
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

// 2.14
func IsComponentHasVerifiedLicense(d sbom.Document, s *scvsScore) bool {
	totalComponents := len(d.Components())
	if totalComponents == 0 {
		s.setDesc("N/A (no components)")
		return false
	}

	// var countAllValidLicense int
	// for _, comp := range d.Components() {
	// 	for _, licen := range comp.Licenses() {
	// 		if licenses.IsValidLicenseID(licen.Name()) {
	// 			countAllValidLicense++
	// 		}
	// 	}
	// }
	countAllValidLicense := lo.CountBy(d.Components(), func(comp sbom.GetComponent) bool {
		return lo.SomeBy(comp.Licenses(), func(licen licenses.License) bool {
			return licenses.IsValidLicenseID(licen.Name())
		})
	})

	if totalComponents > 0 {
		if countAllValidLicense >= totalComponents {
			s.setDesc(fmt.Sprintf("%d/%d comp has valid Licenses", countAllValidLicense, totalComponents))
			return true
		}
	}
	s.setDesc(fmt.Sprintf("%d/%d comp has valid Licenses", countAllValidLicense, totalComponents))
	return false
}

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

// 2.16
func IsComponentContainsModificationChanges(d sbom.Document, s *scvsScore) bool { return false } // 2.17

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
} // 2.18
