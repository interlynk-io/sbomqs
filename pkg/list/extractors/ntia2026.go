// Copyright 2026 Interlynk.io
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

// NTIA Minimum Elements (2026) extractors.
//
// The list command shows actual field values; it does not enforce version
// requirements or algorithm rules (that is the scorer's job).

package extractors

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// ============================================================
// NTIA 2026 — SBOM-level extractors (DocExtractor)
// ============================================================

// NTIA2026SBOMDataFormat reports the SBOM spec type and file format.
func NTIA2026SBOMDataFormat(doc sbom.Document) (bool, string, error) {
	spec := strings.TrimSpace(doc.Spec().GetSpecType())
	format := strings.TrimSpace(doc.Spec().FileFormat())
	if spec == "" {
		return false, "not declared", nil
	}
	if format != "" {
		return true, fmt.Sprintf("%s (%s)", spec, format), nil
	}
	return true, spec, nil
}

// NTIA2026SBOMSpecVersion reports the SBOM specification version.
func NTIA2026SBOMSpecVersion(doc sbom.Document) (bool, string, error) {
	ver := strings.TrimSpace(doc.Spec().GetVersion())
	if ver == "" || ver == "SpecVersion(0)" {
		return false, "not declared", nil
	}
	return true, ver, nil
}

// NTIA2026SBOMAuthors reports the first person or organization author.
// Tool entries are NOT accepted (mirrors profiles.NTIA2026SBOMAuthors).
func NTIA2026SBOMAuthors(doc sbom.Document) (bool, string, error) {
	for _, a := range doc.Authors() {
		if a == nil {
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

// NTIA2026SBOMToolName reports the first tool name declared in the SBOM.
func NTIA2026SBOMToolName(doc sbom.Document) (bool, string, error) {
	for _, t := range doc.Tools() {
		name := strings.TrimSpace(t.GetName())
		if name != "" {
			return true, name, nil
		}
	}
	return false, "missing", nil
}

// NTIA2026SBOMToolVersion reports the first tool version declared in the SBOM.
func NTIA2026SBOMToolVersion(doc sbom.Document) (bool, string, error) {
	for _, t := range doc.Tools() {
		version := strings.TrimSpace(t.GetVersion())
		if version != "" {
			return true, version, nil
		}
	}
	return false, "missing", nil
}

// NTIA2026SBOMVersion reports the author-assigned SBOM document version.
// For CycloneDX: checks the version segment of the URI.
// For SPDX: always N/A (not supported by spec).
func NTIA2026SBOMVersion(doc sbom.Document) (bool, string, error) {
	spec := doc.Spec().GetSpecType()
	if spec == string(sbom.SBOMSpecCDX) {
		uri := strings.TrimSpace(doc.Spec().GetURI())
		parts := strings.Split(uri, "/")
		if len(parts) >= 2 {
			ver := strings.TrimSpace(parts[len(parts)-1])
			if ver != "" {
				return true, ver, nil
			}
		}
		return false, "missing", nil
	}
	return false, "N/A (SPDX does not support author-assigned versions)", nil
}

// NTIA2026SBOMTimestamp reports the SBOM creation timestamp.
func NTIA2026SBOMTimestamp(doc sbom.Document) (bool, string, error) {
	return BSIV21SBOMTimestamp(doc)
}

// NTIA2026SBOMGenerationContext reports the generation context.
// CDX: lifecycle phases. SPDX v2.x: creationInfo.comment. SPDX 3.x: lifecycles or comment.
func NTIA2026SBOMGenerationContext(doc sbom.Document) (bool, string, error) {
	spec := doc.Spec().GetSpecType()
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == string(sbom.SBOMSpecCDX) || (spec == string(sbom.SBOMSpecSPDX) && strings.HasPrefix(ver, "3.")) {
		lifecycles := doc.Lifecycles()
		if len(lifecycles) > 0 {
			return true, strings.Join(lifecycles, ", "), nil
		}
	}

	if spec == string(sbom.SBOMSpecSPDX) {
		if c := doc.Spec().GetComment(); c != "" {
			return true, c, nil
		}
	}

	return false, "missing", nil
}

// NTIA2026SBOMRelationships reports the primary component's direct dependencies.
func NTIA2026SBOMRelationships(doc sbom.Document) (bool, string, error) {
	return NTIASBOMRelationships(doc)
}

// NTIA2026SBOMSignature reports whether the SBOM has a digital signature.
func NTIA2026SBOMSignature(doc sbom.Document) (bool, string, error) {
	sig := doc.Signature()
	if sig != nil {
		return true, "present", nil
	}
	return false, "missing", nil
}

// ============================================================
// NTIA 2026 — component-level extractors (CompExtractor)
// ============================================================

// NTIA2026CompName reports the component name.
func NTIA2026CompName(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return BSIV21CompName(nil, comp)
}

// NTIA2026CompVersion reports the component version.
func NTIA2026CompVersion(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return BSIV21CompVersion(nil, comp)
}

// NTIA2026CompUniqID reports unique identifiers (PURL or CPE).
func NTIA2026CompUniqID(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	return BSIV20CompOtherIdentifiers(nil, comp)
}

// NTIA2026CompProducer reports the component producer.
// Priority: supplier → manufacturer → author.
// Accepts name, email, or URL as valid producer identifiers.
func NTIA2026CompProducer(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	// 1. Supplier
	if s := comp.Suppliers(); !s.IsAbsent() {
		name := strings.TrimSpace(s.GetName())
		if name != "" {
			return true, name, nil
		}
		email := strings.TrimSpace(s.GetEmail())
		if email != "" {
			return true, email, nil
		}
		url := strings.TrimSpace(s.GetURL())
		if url != "" {
			return true, url, nil
		}
	}

	// 2. Manufacturer
	if m := comp.Manufacturer(); !m.IsAbsent() {
		name := strings.TrimSpace(m.GetName())
		if name != "" {
			return true, name, nil
		}
		email := strings.TrimSpace(m.GetEmail())
		if email != "" {
			return true, email, nil
		}
		url := strings.TrimSpace(m.GetURL())
		if url != "" {
			return true, url, nil
		}
	}

	// 3. Author
	for _, a := range comp.Authors() {
		if a == nil {
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

// NTIA2026CompHashValue reports all hash values on a component.
func NTIA2026CompHashValue(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	checksums := comp.GetChecksums()
	if len(checksums) == 0 {
		return false, "missing", nil
	}
	var values []string
	for _, cs := range checksums {
		v := strings.TrimSpace(cs.GetContent())
		if v != "" {
			values = append(values, v)
		}
	}
	if len(values) > 0 {
		return true, strings.Join(values, ", "), nil
	}
	return false, "missing", nil
}

// NTIA2026CompHashAlgo reports all hash algorithms on a component.
func NTIA2026CompHashAlgo(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	checksums := comp.GetChecksums()
	if len(checksums) == 0 {
		return false, "missing", nil
	}
	var algos []string
	seen := make(map[string]bool)
	for _, cs := range checksums {
		algo := strings.TrimSpace(cs.GetAlgo())
		if algo != "" && !seen[algo] {
			seen[algo] = true
			algos = append(algos, algo)
		}
	}
	if len(algos) > 0 {
		return true, strings.Join(algos, ", "), nil
	}
	return false, "missing", nil
}

// NTIA2026CompLicense reports declared licenses on a component.
func NTIA2026CompLicense(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	var parts []string
	for _, l := range comp.DeclaredLicenses() {
		if l == nil {
			continue
		}
		if id := strings.TrimSpace(l.ShortID()); id != "" {
			parts = append(parts, id)
		}
	}
	if len(parts) > 0 {
		return true, strings.Join(parts, ", "), nil
	}
	return false, "missing", nil
}
