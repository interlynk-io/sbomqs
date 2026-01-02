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

// Provenance category extractors.
// These checks look at who created the SBOM and when: authors, tools,
// creation time, SBOM supplier, SBOM creation type, i.e build type
// and related metadata such as SBOM Namespace.
package extractors

import (
	"fmt"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/catalog"
	commonV2 "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/formulae"
	"github.com/samber/lo"
)

// SBOMCreationTime: document has a valid ISO-8601 timestamp (RFC3339/RFC3339Nano).
// `Created` for SPDX and `metadata.timestamp` for CDX
func SBOMCreationTimestamp(doc sbom.Document) catalog.ComprFeatScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("timestamp"),
			Ignore: false,
		}
	}

	// accept both RFC3339 and RFC3339Nano
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, ts); err2 != nil {
			return catalog.ComprFeatScore{
				Score:  formulae.BooleanScore(false),
				Desc:   "fix timestamp format",
				Ignore: false,
			}
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(true),
		Desc:   "complete",
		Ignore: false,
	}
}

// SBOMAuthor represents an legal entity created an SBOM.
// SPDX: Creator.(Person/Organization); CDX: metadata.(authors/author)
func SBOMAuthors(doc sbom.Document) catalog.ComprFeatScore {
	if commonV2.IsSBOMAuthorEntity(doc) {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(true),
			Desc:   "complete",
			Ignore: false,
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.MissingField("author"),
		Ignore: false,
	}
}

// SBOMCreationTool: tool name AND version(represents complete tool) present for at least one tool.
// SPDX: Creator.Tool; CDX: metadata.tools/tool
func SBOMCreationTool(doc sbom.Document) catalog.ComprFeatScore {
	tools := doc.Tools()
	if len(tools) == 0 {
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("tool"),
			Ignore: false,
		}
	}

	var (
		withNameAndVersion int
		missingName        int
		missingVersion     int
	)

	for _, t := range tools {
		name := strings.TrimSpace(t.GetName())
		ver := strings.TrimSpace(t.GetVersion())

		switch {
		case name != "" && ver != "":
			withNameAndVersion++
		case name == "" && ver != "":
			missingName++
		case name != "" && ver == "":
			missingVersion++
		}
	}

	// Scoring rule:
	// - Full-score: at least one tool has both name+version.
	// - Half-score: no complete tool, but at least one has only name.
	// - No-score: only versions or nothing present.
	var score float64
	var desc string

	switch {
	case withNameAndVersion > 0:
		score = formulae.BooleanScore(true)
		desc = "complete"
	case missingVersion > 0:
		score = 5.0
		desc = fmt.Sprintf("add version to %d tools", missingVersion)
	case missingName > 0:
		score = 0.0
		desc = fmt.Sprintf("add name to %d tools", missingName)
	default:
		score = 0.0
		desc = "add tool"
	}

	return catalog.ComprFeatScore{
		Score:  score,
		Desc:   desc,
		Ignore: false,
	}
}

// SBOMSupplier: CDX-only (supplier/manufacturer in metadata).
// SPDX has no doc-level supplier,  N/A for SPDX.
// For CDX: missing supplier is a FAIL (score 0, Ignore=false).
func SBOMSupplier(doc sbom.Document) catalog.ComprFeatScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		// N/A for SPDX
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: false,
		}

	case string(sbom.SBOMSpecCDX):
		s := doc.Supplier()
		if s != nil {
			hasName := strings.TrimSpace(s.GetName()) != ""
			hasEmail := strings.TrimSpace(s.GetEmail()) != "" || strings.TrimSpace(s.GetURL()) != ""

			if hasName || hasEmail {
				return catalog.ComprFeatScore{
					Score:  formulae.BooleanScore(true),
					Desc:   "complete",
					Ignore: false,
				}
			}
		}
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("supplier"),
			Ignore: false,
		}
	}

	// Unknown spec → treat as not applicable to be safe (optional)
	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}

// SBOMNamespace: required for both specs.
// SPDX: document namespace; CDX: serialNumber/version.
func SBOMNamespace(doc sbom.Document) catalog.ComprFeatScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		ns := strings.TrimSpace(doc.Spec().GetURI())
		if ns != "" {
			return catalog.ComprFeatScore{
				Score:  formulae.BooleanScore(true),
				Desc:   formulae.PresentField("namespace"),
				Ignore: false,
			}
		}
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("namespace"),
			Ignore: false,
		}

	case string(sbom.SBOMSpecCDX):
		uri := strings.TrimSpace(doc.Spec().GetURI())
		fmt.Println("uri: ", uri)
		if uri != "" {
			fmt.Println("URI Present: ", uri)
			return catalog.ComprFeatScore{
				Score:  formulae.BooleanScore(true),
				Desc:   formulae.PresentField("namespace"),
				Ignore: false,
			}
		}
		fmt.Println("URI absent: ", uri)

		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("namespace"),
			Ignore: false,
		}
	}

	// Unknown spec → fail closed (optional: set Ignore=true if you prefer)
	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}

// SBOMLifeCycle: CDX-only (metadata.lifecycles/phase). N/A for SPDX.
func SBOMLifeCycle(doc sbom.Document) catalog.ComprFeatScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: false,
		}

	case string(sbom.SBOMSpecCDX):
		phases := doc.Lifecycles()
		if len(phases) == 0 {
			return catalog.ComprFeatScore{
				Score:  formulae.BooleanScore(false),
				Desc:   formulae.MissingField("lifecycle"),
				Ignore: false,
			}
		}

		hasValidPhase := false

		for _, p := range phases {
			phase := strings.ToLower(strings.TrimSpace(p))
			if phase == "" {
				continue
			}

			if lo.Contains(sbom.CdxSupportedLifecycle, phase) {
				hasValidPhase = true
				break
			}
		}

		if hasValidPhase {
			return catalog.ComprFeatScore{
				Score:  formulae.BooleanScore(true),
				Desc:   "complete",
				Ignore: false,
			}
		}

		return catalog.ComprFeatScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "add valid lifecycle",
			Ignore: false,
		}
	}

	return catalog.ComprFeatScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}
