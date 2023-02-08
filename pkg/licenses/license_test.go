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

package licenses

import "testing"

func TestRestrictedLicense(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  bool
	}{
		{"Is GPL-3.0-or-later is restricted license", "GPL-3.0-or-later", true},
		{"Is LGPL-3.0-or-later is restricted license", "LGPL-3.0-or-later", true},
		{"Is BSD-3-Clause is restricted license", "BSD-3-Clause", false},
		{"Is Apache-2.0 WITH LLVM-exception restricted license", "Apache-2.0 WITH LLVM-exception", false},
	}
	// The execution loop
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ans := RestrictedLicense(tt.input)
			if ans != tt.want {
				t.Errorf("got %t, want %t", ans, tt.want)
			}
		})
	}
}
