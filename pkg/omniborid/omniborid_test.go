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
package omniborid

import (
	"testing"
)

func TestValidOMNIBORID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"Is empty value a valid OMNIBORID", "", false},
		{"Is XYZ a valid OMNIBORID", "xyz", false},
		{"Is gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3 a valid OMNIBORID", "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", true},
		{"Is gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a a valid OMNIBORID", "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			omniInput := NewOmni(tt.input)
			if omniInput.Valid() != tt.want {
				t.Errorf("got %t, want %t", omniInput.Valid(), tt.want)
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
		{"Empty OMNIBORID value", "", ""},
		{"Valid OMNIBORID", "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			omniInput := NewOmni(tt.input)
			if omniInput.String() != tt.want {
				t.Errorf("got %s, want %s", omniInput.String(), tt.want)
			}
		})
	}
}
