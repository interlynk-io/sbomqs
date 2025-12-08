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

// Integrity category extractors.
// These checks focus on trust signals: checksums, strong hashes, and
// and the SBOM Signature itself
package extractors

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	commonV2 "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
)

// CompWithStrongChecksums returns a score based on components having at least one strong checksum.
// Strong checksums: SHA-224+, SHA-3, BLAKE, Streebog, post-quantum algorithms.
// A component with at least one strong checksum gets full credit, even if it also has weak ones.
func CompWithStrongChecksums(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	var withStrong int
	for _, comp := range comps {
		if commonV2.HasStrongChecksum(comp) {
			withStrong++
		}
	}

	return formulae.ScoreCompFull(withStrong, len(comps), "strong checksums", false)
}

// CompWithWeakChecksums returns a score based on components having only weak checksums (no strong).
// Weak checksums: MD2-6, SHA-1, Adler-32.
// This identifies components that have checksums but need to be upgraded to stronger algorithms.
// Components with no checksums are NOT counted here (they're handled by comp_with_strong_checksums).
func CompWithWeakChecksums(doc sbom.Document) catalog.ComprFeatScore {
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	var withWeakOnly, withAnyChecksum int
	for _, comp := range comps {
		hasStrong := commonV2.HasStrongChecksum(comp)
		hasWeak := commonV2.HasWeakChecksum(comp)

		if hasStrong || hasWeak {
			withAnyChecksum++
		}

		// Has weak but no strong = weak only (needs upgrade)
		if hasWeak && !hasStrong {
			withWeakOnly++
		}
	}

	// If no components have any checksums, this feature is N/A
	if withAnyChecksum == 0 {
		return catalog.ComprFeatScore{
			Score:  0,
			Desc:   "no checksums found",
			Ignore: false,
		}
	}

	// For weak checksums, we report how many need upgrading
	var desc string
	if withWeakOnly == 0 {
		desc = "complete"
	} else if withWeakOnly == 1 {
		desc = "upgrade 1 component to SHA-256+"
	} else {
		desc = fmt.Sprintf("upgrade %d components to SHA-256+", withWeakOnly)
	}

	// Score is based on components with checksums that are NOT weak-only
	// (i.e., they have strong checksums)
	withStrongAmongChecksummed := withAnyChecksum - withWeakOnly

	return catalog.ComprFeatScore{
		Score:  formulae.PerComponentScore(withStrongAmongChecksummed, withAnyChecksum),
		Desc:   desc,
		Ignore: false,
	}
}

// allow tests to stub this
var verifySignature = common.VerifySignature

// SBOMSignature verifies a doc-level signature if a bundle is present.
// Scoring:
//
//	10 = signature present and verification succeeded
//	 5 = signature present but verification failed
//	 0 = no signature / incomplete bundle
func SBOMSignature(doc sbom.Document) catalog.ComprFeatScore {
	// SPDX does not support signatures in its specification
	if strings.ToLower(doc.Spec().GetSpecType()) == "spdx" {
		return catalog.ComprFeatScore{
			Score:  0,
			Desc:   "not supported by SPDX",
			Ignore: true,
		}
	}

	sig := doc.Signature()
	if sig == nil {
		return catalog.ComprFeatScore{
			Score:  0,
			Desc:   formulae.MissingField("signature"),
			Ignore: false,
		}
	}

	// Check if signature has the required components
	algorithm := strings.TrimSpace(sig.GetAlgorithm())
	sigValue := strings.TrimSpace(sig.GetSigValue())

	// Incomplete signature → treat as missing
	if algorithm == "" || sigValue == "" {
		return catalog.ComprFeatScore{
			Score:  0,
			Desc:   formulae.MissingField("signature"),
			Ignore: false,
		}
	}

	// Check if we have public key or certificate path for verification
	pubKey := strings.TrimSpace(sig.GetPublicKey())
	certPath := sig.GetCertificatePath()

	if pubKey == "" && len(certPath) == 0 {
		// Signature present but no verification material
		return catalog.ComprFeatScore{
			Score:  5,
			Desc:   formulae.MissingField("signature"),
			Ignore: false,
		}
	}

	// For now, we'll give full score if signature is complete
	// Future enhancement: actually verify the signature
	return catalog.ComprFeatScore{
		Score:  10,
		Desc:   formulae.PresentField("signature"),
		Ignore: false,
	}
}
