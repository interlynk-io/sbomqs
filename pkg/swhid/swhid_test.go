// Copyright 2023 Interlynk.io
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

package swhid

import (
	"testing"
)

func TestValidSWHID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Is empty value a valid SWHID", "", false},
		{"Is XYZ a valid SWHID", "xyz", false},
		{"Is swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2 a valid SWHID", "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2", true},
		{"Is swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2a a valid SWHID", "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swhidInput := NewSWHID(tt.input)
			if swhidInput.Valid() != tt.want {
				t.Errorf("got %t, want %t", swhidInput.Valid(), tt.want)
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
		{"Empty SWHID value", "", ""},
		{"Valid SWHID", "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2", "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swhidInput := NewSWHID(tt.input)
			if swhidInput.String() != tt.want {
				t.Errorf("got %s, want %s", swhidInput.String(), tt.want)
			}
		})
	}
}
