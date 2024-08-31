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

package scorer

import "github.com/interlynk-io/sbomqs/pkg/sbom"

type scvsCheck struct {
	Key      string `yaml:"feature"`
	evaluate func(sbom.Document, *scvsCheck) scvsScore
}

var scvsChecks = []scvsCheck{
	// scvs
	{"A structured, machine readable software bill of materials (SBOM) format is present", scvsSBOMMachineReadableCheck},
	{"SBOM creation is automated and reproducible", scvsSBOMAutomationCreationCheck},
	{"Each SBOM has a unique identifier", scvsSBOMUniqIDCheck},
	{"SBOM has been signed by publisher, supplier, or certifying authority", scvsSBOMSigcheck},
	{"SBOM signature verification exists", scvsSBOMSigCorrectnessCheck},
	{"SBOM signature verification is performed", scvsSBOMSigVerified},
	{"SBOM is timestamped", scvsSBOMTimestampCheck},
	{"SBOM is analyzed for risk", scvsSBOMRiskAnalysisCheck},
	{"SBOM contains a complete and accurate inventory of all components the SBOM describes", scvsSBOMInventoryListCheck},
	{"SBOM contains an accurate inventory of all test components for the asset or application it describes", scvsSBOMTestInventoryListCheck},
	{"SSBOM contains metadata about the asset or software the SBOM describes", scvsSBOMPrimaryCompCheck},
	{"Component identifiers are derived from their native ecosystems (if applicable)", scvsCompHasIdentityIDCheck},
	{"Component point of origin is identified in a consistent, machine readable format (e.g. PURL)", scvsCompHasOriginIDCheck},
	{"Components defined in SBOM have accurate license information", scvsCompHasLicensesCheck},
	{"Components defined in SBOM have valid SPDX license ID's or expressions (if applicable)", scvsCompHasValidLicenseCheck},
	{"Components defined in SBOM have valid copyright statements", scvsCompHasCopyright},
	{"Components defined in SBOM which have been modified from the original have detailed provenance and pedigree information", scvsCompHasModificationCheck},
	{"Components defined in SBOM have one or more file hashes (SHA-256, SHA-512, etc)", scvsCompHashCheck},
}
