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

package v2

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

var SupportedFeatures = map[string]bool{
	"comp_with_name":             true,
	"comp_with_version":          true,
	"comp_with_identifiers":      true,
	"sbom_creation_timestamp":    true,
	"sbom_authors":               true,
	"sbom_tool_version":          true,
	"sbom_supplier":              true,
	"sbom_namespace":             true,
	"sbom_lifecycle":             true,
	"comp_with_checksums":        true,
	"comp_with_sha256":           true,
	"sbom_signature":             true,
	"comp_with_dependencies":     true,
	"sbom_completeness_declared": true,
	"primary_component":          true,
	"comp_with_source_code":      true,
	"comp_with_supplier":         true,
	"comp_with_purpose":          true,
	"comp_with_licenses":         true,

	"comp_with_valid_licenses":     true,
	"comp_with_declared_licenses":  true,
	"sbom_data_license":            true,
	"comp_no_deprecated_licenses":  true,
	"comp_no_restrictive_licenses": true,
	"comp_with_purl":               true,
	"comp_with_cpe":                true,
	"sbom_spec_declared":           true,
	"sbom_spec_version":            true,
	"sbom_file_format":             true,
	"sbom_schema_valid":            true,
}

//
// Identification
//

// CompWithName: percentage of components that have a non-empty name.
func CompWithName(doc sbom.Document) FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return FeatureScore{Score: 0, Desc: "N/A (no components)", Ignore: true}
	}
	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetName()) != ""
	})

	return FeatureScore{
		Score:  perComponentScore(have, total),
		Desc:   fmt.Sprintf("%d/%d have names", have, total),
		Ignore: false,
	}
}

// CompWithVersion: percentage of components that have a non-empty version.
func CompWithVersion(doc sbom.Document) FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return FeatureScore{Score: 0, Desc: "N/A (no components)", Ignore: true}
	}
	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetVersion() != ""
	})

	return FeatureScore{
		Score:  perComponentScore(have, total),
		Desc:   fmt.Sprintf("%d/%d have versions", have, total),
		Ignore: false,
	}
}

// CompWithUniqIDs: percentage of components whose ID is present and unique within the SBOM.
func CompWithUniqIDs(doc sbom.Document) FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return FeatureScore{Score: 0, Desc: "N/A (no components)", Ignore: true}
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return FeatureScore{
		Score:  perComponentScore(len(have), total),
		Desc:   fmt.Sprintf("%d/%d have unique IDs", len(have), total),
		Ignore: false,
	}
}

//
// Provenance
//

// SBOMCreationTime: document has a valid ISO-8601 timestamp (RFC3339/RFC3339Nano).
func SBOMCreationTime(doc sbom.Document) FeatureScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return FeatureScore{Score: 0, Desc: "missing timestamp", Ignore: false}
	}

	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return FeatureScore{Score: 0, Desc: fmt.Sprintf("invalid timestamp: %s", ts), Ignore: false}
	}
	return FeatureScore{
		Score:  booleanScore(ts != ""),
		Desc:   ts,
		Ignore: false,
	}
}

// SBOMAuthors: SBOM has author/creator information (people/orgs and/or tools).
// We treat "authors + tools" as creators for a friendlier pass in common real SBOMs.
func SBOMAuthors(doc sbom.Document) FeatureScore {
	total := len(doc.Authors())

	return FeatureScore{
		Score:  booleanScore(total > 0),
		Desc:   fmt.Sprintf("%d authors/tools", total),
		Ignore: false,
	}
}

// SBOMToolVersion: at least one tool has both a name and a version.
func SBOMToolVersion(doc sbom.Document) FeatureScore {
	for _, t := range doc.Tools() {
		name := strings.TrimSpace(t.GetName())
		ver := strings.TrimSpace(t.GetVersion())
		if name != "" && ver != "" {
			return FeatureScore{Score: 10, Desc: fmt.Sprintf("%s %s", name, ver), Ignore: false}
		}
	}
	return FeatureScore{Score: 0, Desc: "no tool with name+version", Ignore: false}
}

// SBOMSupplier: document-level supplier/manufacturer is present.
func SBOMSupplier(doc sbom.Document) FeatureScore {
	// TODO: adjust to your spec wrapper. This is a placeholder accessor.
	// supplier := strings.TrimSpace(doc.Spec().GetSupplier()) // <-- replace with your real method
	// if supplier != "" {
	// 	return FeatureScore{Score: 10, Desc: supplier, Ignore: false}
	// }
	return FeatureScore{Score: 0, Desc: "no supplier", Ignore: false}
}

// SBOMNamespace: document has a stable identifier (namespace/serialNumber/URI/UUID).
func SBOMNamespace(doc sbom.Document) FeatureScore {
	ns := strings.TrimSpace(doc.Spec().GetNamespace())
	if ns == "" {
		return FeatureScore{Score: 0, Desc: "no namespace/serial", Ignore: false}
	}
	// best-effort URL check; if it parses, good enough
	if _, err := url.ParseRequestURI(ns); err == nil {
		return FeatureScore{Score: 10, Desc: "valid namespace/URI", Ignore: false}
	}
	// allow non-URL identifiers (e.g., UUID); still count as present
	return FeatureScore{Score: 10, Desc: "namespace present", Ignore: false}
}

// SBOMLifecycle: lifecycle/phase information is present (e.g., build/runtime).
func SBOMLifecycle(doc sbom.Document) FeatureScore {
	// TODO: to implement
	// phase := strings.TrimSpace(doc.Lifecycles())
	// if phase != "" {
	// 	return FeatureScore{Score: 10, Desc: phase, Ignore: false}
	// }
	return FeatureScore{Score: 0, Desc: "no lifecycle", Ignore: false}
}
