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
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

func (r *Reporter) basicReport() {
	for _, r := range r.Results {
		format := r.Meta.FileFormat
		spec := r.Meta.Spec
		version := r.Meta.SpecVersion

		if spec == string(sbom.SBOMSpecSPDX) {
			version = strings.Replace(version, "SPDX-", "", 1)
		}

		// Handle profile mode
		if r.Profiles != nil && len(r.Profiles.ProfResult) > 0 {
			for _, prof := range r.Profiles.ProfResult {
				fmt.Printf("%0.1f\t%s\t%s\t%s\t%s\t%s\n", prof.InterlynkScore, prof.Grade, prof.Name, version, format, r.Meta.Filename)
			}
		} else if r.Comprehensive != nil {
			// Handle comprehensive mode
			fmt.Printf("%0.1f\t%s\t%s\t%s\t%s\n", r.Comprehensive.InterlynkScore, r.Comprehensive.Grade, version, format, r.Meta.Filename)
		}
	}
}
