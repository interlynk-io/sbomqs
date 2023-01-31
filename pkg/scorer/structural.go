// Copyright 2023 Interlynk.io
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

func specScore(d sbom.Document) score {
	s := newScore(CategoryStrucutral, string(spec))

	specs := sbom.SupportedSBOMSpecs()
	s.setDesc(fmt.Sprintf("provided sbom is in a supported sbom format of %s", strings.Join(specs, ",")))

	for _, spec := range specs {
		if d.Spec().Name() == spec {
			s.setScore(10.0)
		}
	}
	return *s
}

func specVersionScore(d sbom.Document) score {
	s := newScore(CategoryStrucutral, string(specVersion))

	versions := sbom.SupportedSBOMSpecVersions(d.Spec().Name())
	s.setDesc(fmt.Sprintf("provided sbom should be in supported spec version for spec:%s and versions: %s", d.Spec().Version(), strings.Join(versions, ",")))

	for _, ver := range versions {
		if d.Spec().Version() == ver {
			s.setScore(10.0)
		}
	}

	return *s
}

func specFileFormatScore(d sbom.Document) score {
	s := newScore(CategoryStrucutral, string(specFileFormat))

	formats := sbom.SupportedSBOMFileFormats(d.Spec().Name())
	s.setDesc(fmt.Sprintf("provided sbom should be in supported file format for spec: %s and version: %s", d.Spec().FileFormat(), strings.Join(formats, ",")))

	for _, format := range formats {
		if d.Spec().FileFormat() == format {
			s.setScore(10.0)
		}
	}
	return *s
}

func specParsableScore(d sbom.Document) score {
	s := newScore(CategoryStrucutral, string(specIsParsable))
	s.setDesc("provided sbom is parsable")
	if d.Spec().Parsable() {
		s.setScore(10.0)
	}

	return *s
}
