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

package extractors

import (
	"fmt"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

// SBOMCreationTime: document has a valid ISO-8601 timestamp (RFC3339/RFC3339Nano).
// `Created` for SPDX and `metadata.timestamp` for CDX
func SBOMCreationTimestamp(doc sbom.Document) config.FeatureScore {
	ts := strings.TrimSpace(doc.Spec().GetCreationTimestamp())
	if ts == "" {
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("timestamp"),
			Ignore: false,
		}
	}

	// accept both RFC3339 and RFC3339Nano
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		if _, err2 := time.Parse(time.RFC3339Nano, ts); err2 != nil {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(false),
				Desc:   fmt.Sprintf("invalid timestamp: %s", ts),
				Ignore: false,
			}
		}
	}

	return config.FeatureScore{
		Score:  formulae.BooleanScore(true),
		Desc:   ts,
		Ignore: false,
	}
}

// SBOMAuthor represents an legal entity created an SBOM.
// SPDX: Creator.(Person/Organization); CDX: metadata.(authors/author)
func SBOMAuthors(doc sbom.Document) config.FeatureScore {
	total := len(doc.Authors())

	if total == 0 {
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   "0 authors",
			Ignore: false,
		}
	}

	return config.FeatureScore{
		Score:  formulae.BooleanScore(true),
		Desc:   fmt.Sprintf("%d authors", total),
		Ignore: false,
	}
}

// SBOMCreationTool: tool name AND version present for at least one tool.
// SPDX: Creator.Tool; CDX: metadata.tools/tool
func SBOMCreationTool(doc sbom.Document) config.FeatureScore {
	toolsWithNV := make([]string, 0, len(doc.Tools()))

	for _, t := range doc.Tools() {
		name := strings.TrimSpace(t.GetName())
		ver := strings.TrimSpace(t.GetVersion())
		if name != "" && ver != "" {
			toolsWithNV = append(toolsWithNV, name+"-"+ver)
		}
	}

	if len(toolsWithNV) == 0 {
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("tool"),
			Ignore: false,
		}
	}

	return config.FeatureScore{
		Score:  formulae.BooleanScore(true),
		Desc:   strings.Join(toolsWithNV, ", "),
		Ignore: false,
	}
}

// SBOMSupplier: CDX-only (supplier/manufacturer in metadata).
// SPDX has no doc-level supplier,  N/A for SPDX.
// For CDX: missing supplier is a FAIL (score 0, Ignore=false).
func SBOMSupplier(doc sbom.Document) config.FeatureScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		// N/A for SPDX
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: true,
		}

	case string(sbom.SBOMSpecCDX):
		s := doc.Supplier()
		hasName := strings.TrimSpace(s.GetName()) != ""
		hasContact := strings.TrimSpace(s.GetEmail()) != "" || strings.TrimSpace(s.GetURL()) != ""

		if hasName && hasContact {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(true),
				Desc:   formulae.PresentField("supplier"),
				Ignore: false,
			}
		}
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("supplier"),
			Ignore: false,
		}
	}

	// Unknown spec → treat as not applicable to be safe (optional)
	return config.FeatureScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}

// SBOMNamespace: required for both specs.
// SPDX: document namespace; CDX: serialNumber/version.
func SBOMNamespace(doc sbom.Document) config.FeatureScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		ns := strings.TrimSpace(doc.Spec().GetNamespace())
		if ns != "" {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(true),
				Desc:   formulae.PresentField("namespace"),
				Ignore: false,
			}
		}
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("namespace"),
			Ignore: false,
		}

	case string(sbom.SBOMSpecCDX):
		uri := strings.TrimSpace(doc.Spec().GetURI())
		if uri != "" {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(true),
				Desc:   formulae.PresentField("namespace"),
				Ignore: false,
			}
		}
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("namespace"),
			Ignore: false,
		}
	}

	// Unknown spec → fail closed (optional: set Ignore=true if you prefer)
	return config.FeatureScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}

// SBOMLifeCycle: CDX-only (metadata.lifecycles/phase). N/A for SPDX.
func SBOMLifeCycle(doc sbom.Document) config.FeatureScore {
	spec := doc.Spec().GetSpecType()

	switch spec {
	case string(sbom.SBOMSpecSPDX):
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.NonSupportedSPDXField(),
			Ignore: true,
		}

	case string(sbom.SBOMSpecCDX):
		phases := doc.Lifecycles()
		if len(phases) > 0 {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(true),
				Desc:   strings.Join(phases, ", "),
				Ignore: false,
			}
		}
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("lifecycle"),
			Ignore: false,
		}
	}

	return config.FeatureScore{
		Score:  formulae.BooleanScore(false),
		Desc:   formulae.UnknownSpec(),
		Ignore: true,
	}
}
