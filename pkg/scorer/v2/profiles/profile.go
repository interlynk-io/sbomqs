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

package profiles

import "github.com/interlynk-io/sbomqs/pkg/scorer/v2/config"

// Profile is one compliance profile (e.g., ntia, bsi-v2.0, oct).
type Profile struct {
	Name        string               `yaml:"name"`      // short key: "ntia"
	FullName    string               `yaml:"full_name"` // display: "NTIA Minimum Elements"
	Description string               `yaml:"description"`
	Features    []config.FeatureSpec `yaml:"features"`
}
