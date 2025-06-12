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

package scorer

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// specCheck checks for spdx or cyclonedx
func specCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	specs := sbom.SupportedSBOMSpecs()
	s.setDesc(fmt.Sprintf("provided sbom is in a supported sbom format of %s", strings.Join(specs, ",")))

	for _, spec := range specs {
		if d.Spec().GetSpecType() == spec {
			s.setScore(10.0)
		}
	}
	return *s
}

func specVersionCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	versions := sbom.SupportedSBOMSpecVersions(d.Spec().GetSpecType())
	s.setDesc(fmt.Sprintf("provided sbom should be in supported spec version for spec:%s and versions: %s", d.Spec().GetVersion(), strings.Join(versions, ",")))

	for _, ver := range versions {
		if d.Spec().GetVersion() == ver {
			s.setScore(10.0)
		}
	}

	return *s
}

func sbomFileFormatCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)

	formats := sbom.SupportedSBOMFileFormats(d.Spec().GetSpecType())
	s.setDesc(fmt.Sprintf("provided sbom should be in supported file format for spec: %s and version: %s", d.Spec().FileFormat(), strings.Join(formats, ",")))

	for _, format := range formats {
		if d.Spec().FileFormat() == format {
			s.setScore(10.0)
		}
	}
	return *s
}

func specParsableCheck(d sbom.Document, c *check) score {
	s := newScoreFromCheck(c)
	s.setDesc("provided sbom is parsable")
	if d.Spec().Parsable() {
		s.setScore(10.0)
	}

	return *s
}
