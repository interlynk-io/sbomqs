// Copyright 2026 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ENISA SBOM Minimum Elements extractors.
//
// The list command shows actual field values; it does not enforce version
// requirements or algorithm rules (that is the scorer's job).
//
// ENISA shares many fields with NTIA 2026 but enforces Person-only rules
// for SBOM Author and Software Producer.

package extractors

import (
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// ============================================================
// ENISA — SBOM-level extractors (DocExtractor)
// ============================================================

// ENISASBOMAuthor reports the first Person-type SBOM author.
// Organization and Tool entries are NOT accepted.
func ENISASBOMAuthor(doc sbom.Document) (bool, string, error) {
	for _, a := range doc.Authors() {
		if a == nil {
			continue
		}
		if !strings.EqualFold(a.GetType(), "person") {
			continue
		}
		name := strings.TrimSpace(a.GetName())
		email := strings.TrimSpace(a.GetEmail())
		url := strings.TrimSpace(a.GetURL())
		if name != "" {
			return true, name, nil
		}
		if email != "" {
			return true, email, nil
		}
		if url != "" {
			return true, url, nil
		}
	}
	return false, "missing", nil
}

// ENISASBOMTimestamp reports the SBOM creation timestamp.
func ENISASBOMTimestamp(doc sbom.Document) (bool, string, error) {
	return NTIA2026SBOMTimestamp(doc)
}

// ENISASBOMToolName reports the first tool name declared in the SBOM.
func ENISASBOMToolName(doc sbom.Document) (bool, string, error) {
	return NTIA2026SBOMToolName(doc)
}

// ENISASBOMGenerationContext reports the generation context.
func ENISASBOMGenerationContext(doc sbom.Document) (bool, string, error) {
	return NTIA2026SBOMGenerationContext(doc)
}

// ============================================================
// ENISA — component-level extractors (CompExtractor)
// ============================================================

// ENISACompName reports the component name.
func ENISACompName(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return NTIA2026CompName(nil, comp)
}

// ENISACompVersion reports the component version.
func ENISACompVersion(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return NTIA2026CompVersion(nil, comp)
}

// ENISACompUniqID reports unique identifiers (PURL, CPE, SWID, SWHID, or OmniBOR ID).
func ENISACompUniqID(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return NTIA2026CompUniqID(nil, comp)
}

// ENISACompProducer reports the Person-type component producer.
// Organization entries are NOT accepted.
func ENISACompProducer(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	for _, a := range comp.Authors() {
		if a == nil {
			continue
		}
		if !strings.EqualFold(a.GetType(), "person") {
			continue
		}
		name := strings.TrimSpace(a.GetName())
		if name != "" {
			return true, name, nil
		}
		email := strings.TrimSpace(a.GetEmail())
		if email != "" {
			return true, email, nil
		}
	}
	return false, "missing", nil
}

// ENISACompHashValue reports all hash values on a component.
func ENISACompHashValue(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return NTIA2026CompHashValue(nil, comp)
}

// ENISACompHashAlgo reports all hash algorithms on a component.
func ENISACompHashAlgo(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return NTIA2026CompHashAlgo(nil, comp)
}

// ENISACompLicense reports declared licenses on a component.
func ENISACompLicense(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return NTIA2026CompLicense(nil, comp)
}

// ENISACompRelationships reports whether the component has declared relationships.
func ENISACompRelationships(doc sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return false, "missing", nil
	}

	if primary.GetID() == comp.GetID() {
		directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
		if len(directDeps) > 0 {
			return true, "primary component declares top-level dependencies", nil
		}
	}

	if comp.HasRelationShips() || comp.CountOfDependencies() > 0 {
		return true, "component has declared relationships", nil
	}

	return false, "missing", nil
}
