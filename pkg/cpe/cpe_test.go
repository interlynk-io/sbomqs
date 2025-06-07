// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cpe

import (
	"testing"
)

func TestValidCPE(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  bool
	}{
		{"Is empty value is valid CPE2.3", "", false},
		{"Is XYZ is valid CPE2.3", "xyz", false},
		{"Is cpe:-2.3:a:CycloneDX:cyclonedx-go:v0.7.0:*:*:*:*:*:*:* is valid CPE2.3", "cpe:-2.3:a:CycloneDX:cyclonedx-go:v0.7.0:*:*:*:*:*:*:*", false},
		{"Is cpe:2.3:a:interlynk:sbomqs:\\(devel\\):*:*:*:*:*:*:* is valid CPE2.3", "cpe:2.3:a:interlynk:sbomqs:\\(devel\\):*:*:*:*:*:*:*", true},
		{"Is cpe:/a:%40thi.ng%2fegf_project:%40thi.ng%2fegf:0.2.0::~~~node.js~~ is valid CPE2.2", "cpe:/a:%40thi.ng%2fegf_project:%40thi.ng%2fegf:0.2.0::~~~node.js~~", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpeinput := NewCPE(tt.input)
			if cpeinput.Valid() != tt.want {
				t.Errorf("got %t, want %t", cpeinput.Valid(), tt.want)
			}
		})
	}
}
