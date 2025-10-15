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

// YAML schema + loader (from file or built-ins).

// File is the root of profiles.yaml
type Config struct {
	SBOMQS   SBOMQSMeta `yaml:"sbomqs"`
	Profiles []Profile  `yaml:"profiles"`
}

// SBOMQSMeta is a small header so we can warn on incompatible files.
type SBOMQSMeta struct {
	Version     string `yaml:"version"`      // e.g., "2.0.0"
	Description string `yaml:"description"`  // free text
	LastUpdated string `yaml:"last_updated"` // 2025-10-15
}
