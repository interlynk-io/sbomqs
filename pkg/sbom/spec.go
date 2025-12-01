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

import (
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
)

//counterfeiter:generate . Spec

// Spec defines the interface for accessing SBOM specification metadata and properties
type Spec interface {
	// GetVersion returns the specification version
	GetVersion() string
	// FileFormat returns the file format of the SBOM
	FileFormat() string
	// Parsable returns whether the SBOM can be successfully parsed
	Parsable() bool
	// GetName returns the name of the SBOM specification
	GetName() string
	// GetSpecType returns the type of the SBOM specification (SPDX, CycloneDX, etc.)
	GetSpecType() string
	// RequiredFields returns whether all required fields are present in the specification
	RequiredFields() bool
	// GetCreationTimestamp returns the creation timestamp of the SBOM
	GetCreationTimestamp() string
	// GetLicenses returns the licenses associated with the SBOM
	GetLicenses() []licenses.License
	// GetNamespace returns the namespace of the SBOM
	GetNamespace() string
	// GetURI returns the URI of the SBOM
	GetURI() string
	// GetOrganization returns the organization that created the SBOM
	GetOrganization() string
	// GetComment returns any comments associated with the SBOM
	GetComment() string
	// GetSpdxID returns the SPDX identifier for the SBOM
	GetSpdxID() string
	// GetExtDocRef returns external document references
	GetExtDocRef() []string
}

// Specs represents the concrete implementation of SBOM specification metadata
type Specs struct {
	Version              string
	Format               string
	SpecType             string
	Name                 string
	isReqFieldsPresent   bool
	Licenses             []licenses.License
	CreationTimestamp    string
	Namespace            string
	URI                  string
	Organization         string
	Comment              string
	Spdxid               string
	ExternalDocReference []string
}

// NewSpec creates a new instance of Specs with default values
func NewSpec() *Specs {
	return &Specs{}
}

// GetOrganization returns the organization that created the SBOM
func (s Specs) GetOrganization() string {
	return s.Organization
}

// GetComment returns any comments associated with the SBOM
func (s Specs) GetComment() string {
	return s.Comment
}

// GetSpdxID returns the SPDX identifier for the SBOM
func (s Specs) GetSpdxID() string {
	return s.Spdxid
}

// GetVersion returns the specification version
func (s Specs) GetVersion() string {
	return s.Version
}

// FileFormat returns the file format of the SBOM
func (s Specs) FileFormat() string {
	return s.Format
}

// Parsable returns whether the SBOM can be successfully parsed
func (s Specs) Parsable() bool {
	return true
}

// GetName returns the name of the SBOM specification
func (s Specs) GetName() string {
	return s.Name
}

// GetSpecType returns the type of the SBOM specification (SPDX, CycloneDX, etc.)
func (s Specs) GetSpecType() string {
	return s.SpecType
}

// RequiredFields returns whether all required fields are present in the specification
func (s Specs) RequiredFields() bool {
	return s.isReqFieldsPresent
}

// GetCreationTimestamp returns the creation timestamp of the SBOM
func (s Specs) GetCreationTimestamp() string {
	return s.CreationTimestamp
}

// GetLicenses returns the licenses associated with the SBOM
func (s Specs) GetLicenses() []licenses.License {
	return s.Licenses
}

// GetNamespace returns the namespace of the SBOM
func (s Specs) GetNamespace() string {
	return s.Namespace
}

// GetURI returns the URI of the SBOM
func (s Specs) GetURI() string {
	return s.URI
}

// GetExtDocRef returns external document references
func (s Specs) GetExtDocRef() []string {
	return s.ExternalDocReference
}
