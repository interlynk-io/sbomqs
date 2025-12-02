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

// FSCTSBOMAuthors: SBOM Author(must)
func FSCTSBOMAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

// SBOM Timestamp(must)
func FSCTSBOMTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

// FSCTSBOMBuildLifecycle checks Build Information
// optional
func FSCTSBOMBuildLifecycle(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMLifeCycle(doc)
}

// FSCTSBOMPrimaryComponent(must)
func FSCTSBOMPrimaryComponent(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMPrimaryComponent(doc)
}

// Component Name(Must)
func FSCTCompName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// Component Version(Must)
func FSCTCompVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// Component Supplier(Must)
func FSCTCompSupplier(doc sbom.Document) catalog.ProfFeatScore {
	return CompSupplier(doc)
}

// Component Other Identifiers(Must)
func FSCTCompUniqID(doc sbom.Document) catalog.ProfFeatScore {
	return CompUniqID(doc)
}

// Component Hash(Must)
func FSCTCompHash(doc sbom.Document) catalog.ProfFeatScore {
	return CompHash(doc)
}

// Component Dependencies(Must)
func FSCTCompDependencies(doc sbom.Document) catalog.ProfFeatScore {
	return CompDependencies(doc)
}

// Component License(Must)
func FSCTCompLicense(doc sbom.Document) catalog.ProfFeatScore {
	return CompLicenses(doc)
}

// Component Copyright(Must)
func FSCTCompCopyright(doc sbom.Document) catalog.ProfFeatScore {
	return CompCopyright(doc)
}
