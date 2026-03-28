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

// NTIA Minimum Elements (2021) extractors.
//
// Feature keys and scorer equivalents:
//
//   comp_supplier      → NTIACompWithSupplier   (supplier preferred, manufacturer fallback)
//   comp_name          → NTIACompWithName        (reuses BSIV21CompName in registry)
//   comp_version       → NTIACompWithVersion     (reuses BSIV21CompVersion in registry)
//   comp_uniq_id       → NTIACompWithUniqID      (reuses BSIV20CompOtherIdentifiers in registry)
//   sbom_relationships → NTIASBOMWithDependencyRelationships
//   sbom_authors       → NTIASBOMWithAuthors     (authors → tools → supplier → manufacturer)
//   sbom_timestamp     → NTIASBOMWithTimeStamp   (reuses BSIV21SBOMTimestamp in registry)
//
// The list command shows actual field values; it does not enforce algorithm
// or format requirements (that is the scorer's job).

package extractors

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// ntiaContactSummary builds a compact "name, email, url" string, omitting empty fields.
func ntiaContactSummary(name, email, url string) string {
	var parts []string
	if name != "" {
		parts = append(parts, name)
	}
	if email != "" {
		parts = append(parts, email)
	}
	if url != "" {
		parts = append(parts, url)
	}
	return strings.Join(parts, ", ")
}

// ============================================================
// NTIA 2021 — SBOM-level extractors (DocExtractor)
// ============================================================

// NTIASBOMAuthors reports the first usable author/creator identity on the SBOM.
//
// Priority order (mirrors profiles.NTIASBOMWithAuthors):
//  1. Explicit authors — any entry with a non-empty name or email
//  2. Creator tools — name+version preferred; name-only accepted
//  3. SBOM-level supplier — any non-empty name, email, or URL
//  4. SBOM-level manufacturer — same
func NTIASBOMAuthors(doc sbom.Document) (bool, string, error) {
	// 1. Explicit authors
	for _, a := range doc.Authors() {
		if a == nil {
			continue
		}
		name := strings.TrimSpace(a.GetName())
		email := strings.TrimSpace(a.GetEmail())
		if name != "" && email != "" {
			return true, fmt.Sprintf("author: %s <%s>", name, email), nil
		}
		if name != "" {
			return true, fmt.Sprintf("author: %s", name), nil
		}
		if email != "" {
			return true, fmt.Sprintf("author email: %s", email), nil
		}
	}

	// 2. Creator tools
	for _, t := range doc.Tools() {
		name := strings.TrimSpace(t.GetName())
		version := strings.TrimSpace(t.GetVersion())
		if name != "" && version != "" {
			return true, fmt.Sprintf("tool: %s %s", name, version), nil
		}
		if name != "" {
			return true, fmt.Sprintf("tool: %s", name), nil
		}
	}

	// 3. SBOM-level supplier
	if s := doc.Supplier(); s != nil {
		name := strings.TrimSpace(s.GetName())
		email := strings.TrimSpace(s.GetEmail())
		url := strings.TrimSpace(s.GetURL())
		if name != "" || email != "" || url != "" {
			return true, fmt.Sprintf("supplier: %s", ntiaContactSummary(name, email, url)), nil
		}
	}

	// 4. SBOM-level manufacturer
	if m := doc.Manufacturer(); m != nil {
		name := strings.TrimSpace(m.GetName())
		email := strings.TrimSpace(m.GetEmail())
		url := strings.TrimSpace(m.GetURL())
		if name != "" || email != "" || url != "" {
			return true, fmt.Sprintf("manufacturer: %s", ntiaContactSummary(name, email, url)), nil
		}
	}

	return false, "missing", nil
}

// NTIASBOMRelationships reports the primary component's direct DEPENDS_ON relationships.
//
// Logic (mirrors profiles.NTIASBOMWithDependencyRelationships):
//  1. If the primary component has at least one DEPENDS_ON dep → show count + names
//  2. If no direct deps, check composition completeness entries for the primary component
//  3. Otherwise → missing
func NTIASBOMRelationships(doc sbom.Document) (bool, string, error) {
	primary := doc.PrimaryComp()
	if !primary.IsPresent() {
		return false, "no primary component declared", nil
	}

	// 1. Direct DEPENDS_ON dependencies
	directDeps := doc.GetDirectDependencies(primary.GetID(), "DEPENDS_ON")
	if len(directDeps) > 0 {
		count := len(directDeps)
		if count <= 5 {
			names := make([]string, 0, count)
			for _, dep := range directDeps {
				names = append(names, dep.GetName())
			}
			return true, fmt.Sprintf("%d direct deps: %s", count, strings.Join(names, ", ")), nil
		}
		return true, fmt.Sprintf("%d direct deps", count), nil
	}

	// 2. No direct deps — check declared composition completeness
	for _, c := range doc.Composition() {
		if c.Scope() != sbom.ScopeDependencies {
			continue
		}
		for _, depID := range c.Dependencies() {
			if depID == primary.GetID() {
				return true, fmt.Sprintf("no direct deps; completeness declared: %s", string(c.Aggregate())), nil
			}
		}
	}

	return false, "no direct dependencies and no completeness declaration", nil
}

// ============================================================
// NTIA 2021 — component-level extractor (CompExtractor)
// ============================================================

// NTIACompSupplier reports the component supplier or manufacturer.
//
// Supplier is preferred (SPDX: PackageSupplier/PackageOriginator; CDX: supplier).
// Manufacturer is the fallback (CDX: manufacturer; no direct SPDX mapping).
// Shows any non-empty name, email, or URL found.
// Mirrors: profiles.NTIACompWithSupplier
func NTIACompSupplier(_ sbom.Document, comp sbom.GetComponent) (bool, string, error) {
	// Prefer supplier
	if s := comp.Suppliers(); !s.IsAbsent() {
		name := strings.TrimSpace(s.GetName())
		email := strings.TrimSpace(s.GetEmail())
		url := strings.TrimSpace(s.GetURL())
		if name != "" || email != "" || url != "" {
			return true, ntiaContactSummary(name, email, url), nil
		}
	}

	// Fallback: manufacturer
	if m := comp.Manufacturer(); !m.IsAbsent() {
		name := strings.TrimSpace(m.GetName())
		email := strings.TrimSpace(m.GetEmail())
		url := strings.TrimSpace(m.GetURL())
		if name != "" || email != "" || url != "" {
			return true, fmt.Sprintf("manufacturer: %s", ntiaContactSummary(name, email, url)), nil
		}
	}

	return false, "missing", nil
}
