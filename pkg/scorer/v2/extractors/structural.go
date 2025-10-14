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

	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"
	"github.com/interlynk-io/sbomqs/pkg/scorer/v2/formulae"
)

// SBOMWithSpec check for SBOM spec
func SBOMWithSpec(doc sbom.Document) config.FeatureScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))

	if spec == "" {
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("spec"),
			Ignore: false,
		}
	}

	for _, s := range sbom.SupportedSBOMSpecs() {
		if spec == strings.ToLower(strings.TrimSpace(s)) {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(true),
				Desc:   spec,
				Ignore: false,
			}
		}
	}

	return config.FeatureScore{
		Score:  formulae.BooleanScore(false),
		Desc:   fmt.Sprintf("unsupported spec: %s", spec),
		Ignore: false,
	}
}

// SBOMSpecVersion: version supported for this spec?
func SBOMSpecVersion(doc sbom.Document) config.FeatureScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	ver := strings.TrimSpace(doc.Spec().GetVersion())

	if spec == "" || ver == "" {
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("spec/version"),
			Ignore: false,
		}
	}

	supported := sbom.SupportedSBOMSpecVersions(spec)
	for _, v := range supported {
		if ver == v {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(true),
				Desc:   ver,
				Ignore: false,
			}
		}
	}

	return config.FeatureScore{
		Score:  formulae.BooleanScore(false),
		Desc:   fmt.Sprintf("unsupported version: %s (spec %s)", ver, spec),
		Ignore: false,
	}
}

// SBOMFileFormat: file format supported for this spec?
func SBOMFileFormat(doc sbom.Document) config.FeatureScore {
	spec := strings.TrimSpace(strings.ToLower(doc.Spec().GetSpecType()))
	format := strings.TrimSpace(strings.ToLower(doc.Spec().FileFormat()))

	if spec == "" || format == "" {
		return config.FeatureScore{
			Score:  formulae.BooleanScore(false),
			Desc:   formulae.MissingField("file format"),
			Ignore: false,
		}
	}

	supported := sbom.SupportedSBOMFileFormats(spec)
	for _, f := range supported {
		if format == strings.ToLower(strings.TrimSpace(f)) {
			return config.FeatureScore{
				Score:  formulae.BooleanScore(true),
				Desc:   format,
				Ignore: false,
			}
		}
	}

	return config.FeatureScore{
		Score:  formulae.BooleanScore(false),
		Desc:   fmt.Sprintf("unsupported format: %s (spec %s)", format, spec),
		Ignore: false,
	}
}

// SBOMSchemaValid: validate document against official schema for its spec/version.
func SBOMSchemaValid(doc sbom.Document) config.FeatureScore {
	if doc.SchemaValidation() {
		return config.FeatureScore{
			Score:  formulae.BooleanScore(true),
			Desc:   "schema valid",
			Ignore: false,
		}
	}
	return config.FeatureScore{
		Score:  formulae.BooleanScore(false),
		Desc:   "schema invalid",
		Ignore: false,
	}
}
