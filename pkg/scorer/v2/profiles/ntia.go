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

// Automation Support
func SBOMWithAutomationSpec(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAutomationSpec(doc)
}

// Dependency Relationships
func SbomWithDepedencies(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMDepedencies(doc)
}

// SBOM Author
func SbomWithAuthors(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMAuthors(doc)
}

// SBOM Timestamp
func SbomWithTimeStamp(doc sbom.Document) catalog.ProfFeatScore {
	return SBOMCreationTimestamp(doc)
}

// Component Name
func CompWithName(doc sbom.Document) catalog.ProfFeatScore {
	return CompName(doc)
}

// Component Version
func CompWithVersion(doc sbom.Document) catalog.ProfFeatScore {
	return CompVersion(doc)
}

// Component Supplier
func CompWithSupplier(doc sbom.Document) catalog.ProfFeatScore {
	return CompSupplier(doc)
}

// Component Other Identifiers
func CompWithUniqID(doc sbom.Document) catalog.ProfFeatScore {
	return CompUniqID(doc)
}
