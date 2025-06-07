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

package purl

import (
	"testing"
)

func TestValid(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  bool
	}{
		{"Is empty value is valid PURL", "", false},
		{"Is XYZ is valid PURL", "xyz", false},
		{"Is pkg golang/github.com/CycloneDX/cyclonedx-go@v0.7.0 is valid PURL", "pkg,golang/github.com/CycloneDX/cyclonedx-go@v0.7.0", false},
		{"Is pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.7.0 is valid PURL", "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.7.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := NewPURL(tt.input)
			if input.Valid() != tt.want {
				t.Errorf("got %t, want %t", input.Valid(), tt.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  string
	}{
		{"Empty PURL value", "", ""},
		{"valid PURL", "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.7.0", "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.7.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := NewPURL(tt.input)
			if input.String() != tt.want {
				t.Errorf("got %s, want %s", input.String(), tt.want)
			}
		})
	}
}
