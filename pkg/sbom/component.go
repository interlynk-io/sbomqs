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

package sbom

//counterfeiter:generate . Component
import (
	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/licenses"
	"github.com/interlynk-io/sbomqs/pkg/purl"
)

type GetComponent interface {
	GetID() string
	GetName() string
	GetVersion() string
	Cpes() []cpe.CPE
	Purls() []purl.PURL
	Licenses() []licenses.License
	GetChecksums() []GetChecksum
	PrimaryPurpose() string
	RequiredFields() bool
	Suppliers() GetSupplier
	Manufacturer() Manufacturer
	CountOfDependencies() int
	SourceCodeURL() string
	GetDownloadLocationURL() string
	SourceCodeHash() string
	IsPrimaryComponent() bool
	HasRelationShips() bool
	RelationShipState() string
	GetSpdxID() string
	GetFileAnalyzed() bool
	GetCopyRight() string
	GetPackageLicenseDeclared() string
	GetPackageLicenseConcluded() string
	ExternalReferences() []GetExternalReference
}

type Component struct {
	Name                    string
	Version                 string
	cpes                    []cpe.CPE
	purls                   []purl.PURL
	licenses                []licenses.License
	Checksums               []GetChecksum
	purpose                 string
	isReqFieldsPresent      bool
	ID                      string
	Supplier                Supplier
	manufacturer            manufacturer
	dependenciesCount       int
	sourceCodeURL           string
	DownloadLocation        string
	sourceCodeHash          string
	isPrimary               bool
	hasRelationships        bool
	relationshipState       string
	Spdxid                  string
	FileAnalyzed            bool
	CopyRight               string
	PackageLicenseConcluded string
	PackageLicenseDeclared  string
	ExternalRefs            []GetExternalReference
}

func NewComponent() *Component {
	return &Component{}
}

func (c Component) GetName() string {
	return c.Name
}

func (c Component) GetVersion() string {
	return c.Version
}

func (c Component) Purls() []purl.PURL {
	return c.purls
}

func (c Component) Cpes() []cpe.CPE {
	return c.cpes
}

func (c Component) Licenses() []licenses.License {
	return c.licenses
}

func (c Component) GetChecksums() []GetChecksum {
	return c.Checksums
}

func (c Component) PrimaryPurpose() string {
	return c.purpose
}

func (c Component) RequiredFields() bool {
	return c.isReqFieldsPresent
}

func (c Component) GetID() string {
	return c.ID
}

func (c Component) Manufacturer() Manufacturer {
	return c.manufacturer
}

func (c Component) Suppliers() GetSupplier {
	return c.Supplier
}

func (c Component) CountOfDependencies() int {
	return c.dependenciesCount
}

func (c Component) SourceCodeURL() string {
	return c.sourceCodeURL
}

func (c Component) GetDownloadLocationURL() string {
	return c.DownloadLocation
}

func (c Component) SourceCodeHash() string {
	return c.sourceCodeHash
}

func (c Component) IsPrimaryComponent() bool {
	return c.isPrimary
}

func (c Component) HasRelationShips() bool {
	return c.hasRelationships
}

func (c Component) RelationShipState() string {
	return c.relationshipState
}

func (c Component) GetSpdxID() string {
	return c.Spdxid
}

func (c Component) GetFileAnalyzed() bool {
	return c.FileAnalyzed
}

func (c Component) GetCopyRight() string {
	return c.CopyRight
}

func (c Component) GetPackageLicenseConcluded() string {
	return c.PackageLicenseConcluded
}

func (c Component) GetPackageLicenseDeclared() string {
	return c.PackageLicenseDeclared
}

func (c Component) ExternalReferences() []GetExternalReference {
	return c.ExternalRefs
}
