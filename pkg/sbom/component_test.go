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

package sbom

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/cpe"
)

func TestGetCpeFromCompo(t *testing.T) {
	var tests = []struct {
		name  string
		input []cpe.CPE
		want  int
	}{
		{"get cpe from component", []cpe.CPE{"cpe:-2.3:a:CycloneDX:cyclonedx-go:v0.7.0:*:*:*:*:*:*:*"}, 1},
		{"Is XYZ is valid CPE2.3", []cpe.CPE{""}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := component{
				cpes: tt.input,
			}
			if len(tt.input) != len(cp.cpes) {
				t.Errorf("got %d, want %d", len(cp.cpes), len(tt.input))
			}
		})
	}
}
