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

package list

type ListResult struct {
	FilePath         string
	Feature          string
	Missing          bool
	Components       []ComponentResult      // For component-based features
	DocumentProperty DocumentPropertyResult // For SBOM-based features
	Errors           []string
}

type ComponentResult struct {
	Name    string
	Version string
	Values  string
}

type DocumentPropertyResult struct {
	Property string // e.g., "Authors", "Creation Timestamp"
	Value    string // e.g., "John Doe", "2023-01-12T22:06:03Z"
	Present  bool   // Indicates if the property is present
}
