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
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/catalog"
)

var (
	validBsiSpdxVersions = []string{"SPDX-2.3"}
	validBsiCdxVersions  = []string{"1.4", "1.5", "1.6"}
)

// BSISBOMSpec checks SBOM Formats
func BSISBOMSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpec(doc)
}

// BSISBOMSpecVersion checks SBOM Spec Version
func BSISBOMSpecVersion(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMSpecVersion(doc)
}

// BSISBOMBuildLifecycle checks Build Information
func BSISBOMBuildLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMLifeCycle(doc)
}

// BSISBOMWithDepedencies checks SBOM Depth
func BSISBOMWithDepedencies(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMDepedencies(doc)
}

// BSISBOMWithAuthors checks SBOM Creator Info
func BSISBOMWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

// BSISBOMWithTimeStamp checks Creation Time
func BSISBOMWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

// BSISBOMNamespace checks URI/Namespace
func BSISBOMNamespace(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMNamespace(doc)
}

// BSICompWithName checks Component Name
func BSICompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// BSICompWithVersion checks Component Version
func BSICompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// BSICompWithLicenses checks Component License
func BSICompWithLicenses(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// BSICompWithHash checks Component Hash
func BSICompWithHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompHash(doc)
}

// BSICompWithSourceCodeURI checks Component Source URL
func BSICompWithSourceCodeURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeURL(doc)
}

// BSICompWithDownloadURI checks Component Download URL
func BSICompWithDownloadURI(doc sbom.Document) catalog.ProfFeatScore {
	return CompDownloadCodeURL(doc)
}

// BSICompWithSourceCodeHash checks Component Source Hash
func BSICompWithSourceCodeHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompSourceCodeHash(doc)
}

// BSICompWithDependency checks Component Dependencies
func BSICompWithDependency(doc sbom.Document) catalog.ProfFeatScore {
	return CompDependencies(doc)
}
