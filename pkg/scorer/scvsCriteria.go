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
	{"Structured, machine-readable SBOM format", specScvsCheck},
	{"SBOM is timestamped", docWithTimeStampScvsCheck},
	{"Each SBOM has a unique identifier", docWithNamespaceScvsCheck},
	{"Component point of origin is identified in a consistent, machine readable format (e.g. PURL)", compWithUniqIDScvsCheck},
	{"Components defined in SBOM have accurate license information", compWithLicensesScvsCheck},
	{"Components defined in SBOM have one or more file hashes (SHA-256, SHA-512, etc)", compWithChecksumsScvsCheck},
	{"Components defined in SBOM have valid copyright statements", compWithCopyrightScvsCheck},
}
