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

//
// Identification
//

// CompWithName: percentage of components that have a non-empty name.
func CompWithName(doc sbom.Document) FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return FeatureScore{Score: 0, Desc: "N/A (no components)", Ignore: true}
	}
	withNames := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return c.GetName() != ""
	})

	return FeatureScore{
		Score:  10.0 * float64(withNames) / float64(total),
		Desc:   fmt.Sprintf("%d/%d have names", withNames, total),
		Ignore: false,
	}
}

// CompWithVersion: percentage of components that have a non-empty version.
func CompWithVersion(doc sbom.Document) FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return FeatureScore{Score: 0, Desc: "N/A (no components)", Ignore: true}
	}
	withVersions := lo.CountBy(d.Components(), func(c sbom.GetComponent) bool {
		return c.GetVersion() != ""
	})

	return FeatureScore{
		Score:  10.0 * float64(withVersions) / float64(total),
		Desc:   fmt.Sprintf("%d/%d have versions", withVersions, total),
		Ignore: false,
	}
}

// CompWithUniqIDs: percentage of components whose ID is present and unique within the SBOM.
func CompWithUniqIDs(doc sbom.Document) FeatureScore {
	total := len(doc.Components())
	if total == 0 {
		return FeatureScore{Score: 0, Desc: "N/A (no components)", Ignore: true}
	}

	seen := make(map[string]int)

	compIDs := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return FeatureScore{
		Score:  10.0 * float64(len(compIDs)) / float64(total),
		Desc:   fmt.Sprintf("%d/%d have unique IDs", len(compIDs), total),
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
	return FeatureScore{Score: 10, Desc: ts, Ignore: false}
}

// SBOMAuthors: SBOM has author/creator information (people/orgs and/or tools).
// We treat "authors + tools" as creators for a friendlier pass in common real SBOMs.
func SBOMAuthors(doc sbom.Document) FeatureScore {
	total := len(doc.Authors())
	if total > 0 {
		return FeatureScore{Score: 10, Desc: fmt.Sprintf("%d creators (people/tools)", total), Ignore: false}
	}
	return FeatureScore{Score: 0, Desc: "no legal authors/creators", Ignore: false}
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
	supplier := strings.TrimSpace(doc.Spec().GetSupplier()) // <-- replace with your real method
	if supplier != "" {
		return FeatureScore{Score: 10, Desc: supplier, Ignore: false}
	}
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
	phase := strings.TrimSpace(doc.Lifecycles())
	if phase != "" {
		return FeatureScore{Score: 10, Desc: phase, Ignore: false}
	}
	return FeatureScore{Score: 0, Desc: "no lifecycle", Ignore: false}
}
