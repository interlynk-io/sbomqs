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
	Category string `yaml:"category"`
	Key      string `yaml:"feature"`
	evaluate func(sbom.Document, *scvsCheck) scvsScore
}

var scvsChecks = []scvsCheck{
	// scvs
	{string("scvs"), "sbom_spec", specScvsCheck},
	{string("scvs"), "sbom_creation_timestamp", docWithTimeStampScvsCheck},
	{string("scvs"), "sbom_namespace", docWithNamespaceScvsCheck},
	{string("scvs"), "comp_with_uniq_ids", compWithUniqIDScvsCheck},
	{string("scvs"), "comp_with_licenses", compWithLicensesScvsCheck},
	{string("scvs"), "comp_with_checksums", compWithChecksumsScvsCheck},
	{string("scvs"), "comp_with_copyright", compWithCopyrightScvsCheck},
}
