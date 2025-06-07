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

package reporter

import (
	"fmt"
	"strings"
)

func (r *Reporter) simpleReport() {
	for index, path := range r.Paths {
		scores := r.Scores[index]
		doc := r.Docs[index]

		format := doc.Spec().FileFormat()
		spec := doc.Spec().GetSpecType()
		specVersion := doc.Spec().GetVersion()

		if spec == "spdx" {
			specVersion = strings.Replace(specVersion, "SPDX-", "", 1)
		}

		if spec == "cyclonedx" {
			spec = "cdx"
		}

		fmt.Printf("%0.1f\t%s\t%s\t%s\t%s\n", scores.AvgScore(), spec, specVersion, format, path)
	}
}
