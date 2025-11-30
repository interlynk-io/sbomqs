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

package sbom

//counterfeiter:generate . GetVulnerabilities

// GetVulnerabilities defines the interface for accessing vulnerability information in SBOMs
type GetVulnerabilities interface {
	// GetID returns the unique identifier of the vulnerability (e.g., CVE ID)
	GetID() string
}

// Vulnerability represents a concrete implementation of vulnerability information
type Vulnerability struct {
	ID string
}

// GetID returns the unique identifier of the vulnerability (e.g., CVE ID)
func (v Vulnerability) GetID() string {
	return v.ID
}
