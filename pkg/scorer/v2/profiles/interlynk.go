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
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
)

// Identification
func InterCompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

func InterCompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

func InterCompWithUniqueID(doc sbom.Document) catalog.ProfFeatScore {
	return CompUniqID(doc)
}

// Provenance
func InterSBOMTimestamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

func InterSBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

func InterSBOMTOol(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMTool(doc)
}

func InterSBOMSupplier(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSupplier(doc)
}

func InterSBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMNamespace(doc)
}

func InterSBOMLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMLifeCycle(doc)
}

// Integrity
func InterCompWithChecksum(doc sbom.Document) catalog.ProfFeatScore {
	return CompHashSHA1Plus(doc)
}

func InterCompWithChecksum265(doc sbom.Document) catalog.ProfFeatScore {
	return CompSHA256Plus(doc)
}

func InterSBOMSignature(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSignature(doc)
}

// Completeness
func InterCompWithDependencies(doc sbom.Document) catalog.ProfFeatScore {
	return CompDependencies(doc)
}

func InterSBOMCompleteness(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCompleteness(doc)
}

func InterSBOMPrimaryComponent(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMPrimaryComponent(doc)
}

func InterCompWithSourceCode(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeURL(doc)
}

func InterCompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {
	return CompSupplier(doc)
}

func InterCompWithPurpose(doc sbom.Document) catalog.ProfFeatScore {
	return CompPurpose(doc)
}

// Licensing
func InterCompWithLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

func InterCompWithValidLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

func InterCompWithDeclaredLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompDeclaredLicenses(doc)
}

func InterCompWithConcludedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompConcludedLicenses(doc)
}

func InterSBOMDataLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMDataLicense(doc)
}

func InterCompWithNODeprecatedLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompWithNODeprecatedLicenses(doc)
}

func InterCompWithNORestrictiveLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompWithNORestrictiveLicenses(doc)
}

// Vulnerability
func InterCompWithPURL(doc sbom.Document) catalog.ProfFeatScore {
	return CompPURL(doc)
}

func InterCompWithCPE(doc sbom.Document) catalog.ProfFeatScore {
	return CompCPE(doc)
}

// Structural
func InterSBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpec(doc)
}

func InterSBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpecVersion(doc)
}

func InterSBOMFileFormat(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAutomationSpec(doc)
}

func InterSBOMSchema(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSchema(doc)
}
