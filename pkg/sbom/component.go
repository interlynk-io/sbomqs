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

//counterfeiter:generate . GetComponent
import (
	"github.com/interlynk-io/sbomqs/v2/pkg/cpe"
	"github.com/interlynk-io/sbomqs/v2/pkg/licenses"
	"github.com/interlynk-io/sbomqs/v2/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/v2/pkg/purl"
	"github.com/interlynk-io/sbomqs/v2/pkg/swhid"
	"github.com/interlynk-io/sbomqs/v2/pkg/swid"
)

// GetComponent defines the interface for accessing SBOM component information and metadata
type GetComponent interface {
	// GetID returns the unique identifier of the component
	GetID() string
	// GetName returns the name of the component
	GetName() string
	// GetVersion returns the version of the component
	GetVersion() string
	// GetCpes returns the Common Platform Enumeration identifiers for the component
	GetCpes() []cpe.CPE
	// GetPurls returns the Package URL identifiers for the component
	GetPurls() []purl.PURL
	// Swhids returns the Software Heritage identifiers for the component
	Swhids() []swhid.SWHID
	// OmniborIDs returns the OmniBOR identifiers for the component
	OmniborIDs() []omniborid.OMNIBORID
	// Swids returns the Software Identification tags for the component
	Swids() []swid.SWID
	// GetLicenses returns all licenses associated with the component
	GetLicenses() []licenses.License
	// DeclaredLicenses returns the explicitly declared licenses for the component
	DeclaredLicenses() []licenses.License
	// ConcludedLicenses returns the concluded licenses for the component
	ConcludedLicenses() []licenses.License
	// GetChecksums returns the cryptographic checksums for the component
	GetChecksums() []GetChecksum
	// PrimaryPurpose returns the primary purpose classification of the component
	PrimaryPurpose() string
	// RequiredFields returns whether all required fields are present for the component
	RequiredFields() bool
	// Suppliers returns the supplier information for the component
	Suppliers() GetSupplier
	// Authors returns the author information for the component
	Authors() []GetAuthor
	// Manufacturer returns the manufacturer information for the component
	Manufacturer() GetManufacturer
	// CountOfDependencies returns the number of dependencies for the component
	CountOfDependencies() int
	// Deps returns the list of dependency identifiers for the component
	Deps() []string
	// GetSourceCodeURL returns the source code repository URL for the component
	GetSourceCodeURL() string
	// GetDownloadLocationURL returns the download location URL for the component
	GetDownloadLocationURL() string
	// SourceCodeHash returns the hash of the source code for the component
	SourceCodeHash() string
	// IsPrimaryComponent returns whether this component is the primary component in the SBOM
	IsPrimaryComponent() bool
	// HasRelationShips returns whether the component has defined relationships
	HasRelationShips() bool
	// RelationShipState returns the state of relationships for the component
	RelationShipState() string
	// GetSpdxID returns the SPDX identifier for the component
	GetSpdxID() string
	// GetFileAnalyzed returns whether files in the component have been analyzed
	GetFileAnalyzed() bool
	// GetCopyRight returns the copyright information for the component
	GetCopyRight() string
	// GetPackageLicenseDeclared returns the declared license string for the package
	GetPackageLicenseDeclared() string
	// GetPackageLicenseConcluded returns the concluded license string for the package
	GetPackageLicenseConcluded() string
	// ExternalReferences returns external references associated with the component
	ExternalReferences() []GetExternalReference
	// GetComposition returns the composition information for the specified component ID
	// GetCompositions() []GetComposition
}

// Component represents a concrete implementation of SBOM component information and metadata
type Component struct {
	Name                    string
	Version                 string
	Cpes                    []cpe.CPE
	Purls                   []purl.PURL
	Swhid                   []swhid.SWHID
	OmniID                  []omniborid.OMNIBORID
	Swid                    []swid.SWID
	Licenses                []licenses.License
	DeclaredLicense         []licenses.License
	ConcludedLicense        []licenses.License
	Checksums               []GetChecksum
	Purpose                 string
	isReqFieldsPresent      bool
	ID                      string
	Athrs                   []GetAuthor
	Supplier                Supplier
	Manufacture             Manufacturer
	Count                   int
	Dep                     []string
	SourceCodeURL           string
	DownloadLocation        string
	sourceCodeHash          string
	isPrimary               bool
	HasRelationships        bool
	RelationshipState       string
	Spdxid                  string
	FileAnalyzed            bool
	CopyRight               string
	PackageLicenseConcluded string
	PackageLicenseDeclared  string
	ExternalRefs            []GetExternalReference
	// composition             map[string]string
}

// NewComponent creates a new instance of Component with default values
func NewComponent() *Component {
	return &Component{}
}

// GetName returns the name of the component
func (c Component) GetName() string {
	return c.Name
}

// GetVersion returns the version of the component
func (c Component) GetVersion() string {
	return c.Version
}

// GetPurls returns the Package URL identifiers for the component
func (c Component) GetPurls() []purl.PURL {
	return c.Purls
}

// GetCpes returns the Common Platform Enumeration identifiers for the component
func (c Component) GetCpes() []cpe.CPE {
	return c.Cpes
}

// Swhids returns the Software Heritage identifiers for the component
func (c Component) Swhids() []swhid.SWHID {
	return c.Swhid
}

// Swids returns the Software Identification tags for the component
func (c Component) Swids() []swid.SWID {
	return c.Swid
}

// OmniborIDs returns the OmniBOR identifiers for the component
func (c Component) OmniborIDs() []omniborid.OMNIBORID {
	return c.OmniID
}

// GetLicenses returns all licenses associated with the component
func (c Component) GetLicenses() []licenses.License {
	return c.Licenses
}

// DeclaredLicenses returns the explicitly declared licenses for the component
func (c Component) DeclaredLicenses() []licenses.License {
	return c.DeclaredLicense
}

// ConcludedLicenses returns the concluded licenses for the component
func (c Component) ConcludedLicenses() []licenses.License {
	return c.ConcludedLicense
}

// GetChecksums returns the cryptographic checksums for the component
func (c Component) GetChecksums() []GetChecksum {
	return c.Checksums
}

// PrimaryPurpose returns the primary purpose classification of the component
func (c Component) PrimaryPurpose() string {
	return c.Purpose
}

// RequiredFields returns whether all required fields are present for the component
func (c Component) RequiredFields() bool {
	return c.isReqFieldsPresent
}

// GetID returns the unique identifier of the component
func (c Component) GetID() string {
	return c.ID
}

// Manufacturer returns the manufacturer information for the component
func (c Component) Manufacturer() GetManufacturer {
	return c.Manufacture
}

// Suppliers returns the supplier information for the component
func (c Component) Suppliers() GetSupplier {
	return c.Supplier
}

// Authors returns the author information for the component
func (c Component) Authors() []GetAuthor {
	return c.Athrs
}

// CountOfDependencies returns the number of dependencies for the component
func (c Component) CountOfDependencies() int {
	return c.Count
}

// Deps returns the list of dependency identifiers for the component
func (c Component) Deps() []string {
	return c.Dep
}

// GetSourceCodeURL returns the source code repository URL for the component
func (c Component) GetSourceCodeURL() string {
	return c.SourceCodeURL
}

// GetDownloadLocationURL returns the download location URL for the component
func (c Component) GetDownloadLocationURL() string {
	return c.DownloadLocation
}

// SourceCodeHash returns the hash of the source code for the component
func (c Component) SourceCodeHash() string {
	return c.sourceCodeHash
}

// IsPrimaryComponent returns whether this component is the primary component in the SBOM
func (c Component) IsPrimaryComponent() bool {
	return c.isPrimary
}

// HasRelationShips returns whether the component has defined relationships
func (c Component) HasRelationShips() bool {
	return c.HasRelationships
}

// RelationShipState returns the state of relationships for the component
func (c Component) RelationShipState() string {
	return c.RelationshipState
}

// GetSpdxID returns the SPDX identifier for the component
func (c Component) GetSpdxID() string {
	return c.Spdxid
}

// GetFileAnalyzed returns whether files in the component have been analyzed
func (c Component) GetFileAnalyzed() bool {
	return c.FileAnalyzed
}

// GetCopyRight returns the copyright information for the component
func (c Component) GetCopyRight() string {
	return c.CopyRight
}

// GetPackageLicenseConcluded returns the concluded license string for the package
func (c Component) GetPackageLicenseConcluded() string {
	return c.PackageLicenseConcluded
}

// GetPackageLicenseDeclared returns the declared license string for the package
func (c Component) GetPackageLicenseDeclared() string {
	return c.PackageLicenseDeclared
}

// ExternalReferences returns external references associated with the component
func (c Component) ExternalReferences() []GetExternalReference {
	return c.ExternalRefs
}

// // GetComposition returns the composition information for the specified component ID
// func (c Component) GetComposition(componentID string) string {
// 	return c.composition[componentID]
// }
