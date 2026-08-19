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

// Identification category extractors.
// These checks ask how uniquely components can be identified: do they
// have good identifiers like Name, Version and Local Unique IDs
package extractors

import (
	"context"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// CompWithName: percentage of components that have a non-empty name.
func CompWithName(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	doc := input.Doc
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetName()) != ""
	})

	return formulae.ScoreCompFull(have, len(comps), "names", false)
}

// CompWithVersion: percentage of components that have a non-empty version.
func CompWithVersion(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	doc := input.Doc
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.CountBy(doc.Components(), func(c sbom.GetComponent) bool {
		return strings.TrimSpace(c.GetVersion()) != ""
	})

	return formulae.ScoreCompFull(have, len(comps), "versions", false)
}

// CompWithUniqLocalIDs: percentage of components carrying a local ID, such as
// a CycloneDX bom-ref or an SPDXID.
//
// Presence only. Distinctness within the document is not checked, so two
// components sharing a bom-ref both count. This is deliberately a structural
// check and is not the NTIA "Other Unique Identifiers" element, which asks for
// a global lookup key and is implemented by the ntia profile's comp_uniq_id.
func CompWithUniqLocalIDs(_ context.Context, input catalog.EvalInput) catalog.ComprFeatScore {
	doc := input.Doc
	comps := doc.Components()
	if len(comps) == 0 {
		return formulae.ScoreCompNA()
	}

	have := lo.FilterMap(doc.Components(), func(c sbom.GetComponent, _ int) (string, bool) {
		if c.GetID() == "" {
			return "", false
		}
		return strings.Join([]string{doc.Spec().GetNamespace(), c.GetID()}, ""), true
	})

	return formulae.ScoreCompFull(len(have), len(comps), "local IDs", false)
}
