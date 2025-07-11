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

package swid

import (
	"testing"
)

func TestValidSWID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Is empty value a valid SWID", "", false},
		{"Is XYZ a valid SWID", "xyz", true},
		{"Is example-swid a valid SWID", "example-swid", true},
		{"Is example_swid a valid SWID", "example_swid", true},
		{"Is example.swid a valid SWID", "example.swid", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swidInput := NewSWID(tt.input, "example-name")
			if swidInput.Valid() != tt.want {
				t.Errorf("got %t, want %t", swidInput.Valid(), tt.want)
			}
		})
	}
}

func TestGetName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"Get name of SWID", "example-swid", "example-name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swidInput := NewSWID(tt.input, "example-name")
			if swidInput.GetName() != tt.want {
				t.Errorf("got %s, want %s", swidInput.GetName(), tt.want)
			}
		})
	}
}

func TestGetTagID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"Get TagID of SWID", "example-swid", "example-swid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swidInput := NewSWID(tt.input, "example-name")
			if swidInput.GetTagID() != tt.want {
				t.Errorf("got %s, want %s", swidInput.GetTagID(), tt.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"String representation of SWID", "example-swid", "example-swid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swidInput := NewSWID(tt.input, "example-name")
			if swidInput.String() != tt.want {
				t.Errorf("got %s, want %s", swidInput.String(), tt.want)
			}
		})
	}
}
