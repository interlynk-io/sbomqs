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

type GetComponent interface {
	GetID() string
	GetName() string
	GetVersion() string
	GetCpes() []cpe.CPE
	GetPurls() []purl.PURL
	Swhids() []swhid.SWHID
	OmniborIDs() []omniborid.OMNIBORID
	Swids() []swid.SWID
	GetLicenses() []licenses.License
	DeclaredLicenses() []licenses.License
	ConcludedLicenses() []licenses.License
	GetChecksums() []GetChecksum
	PrimaryPurpose() string
	RequiredFields() bool
	Suppliers() GetSupplier
	Authors() []GetAuthor
	Manufacturer() GetManufacturer
	CountOfDependencies() int
	Deps() []string
	GetSourceCodeURL() string
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
	GetComposition(string) string
	GetPrimaryCompInfo() GetPrimaryComp
}

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
	manufacturer            Manufacturer
	Count                   int
	Dep                     []string
	SourceCodeURL           string
	DownloadLocation        string
	sourceCodeHash          string
	isPrimary               bool
	PrimaryCompt            PrimaryComp
	HasRelationships        bool
	RelationshipState       string
	Spdxid                  string
	FileAnalyzed            bool
	CopyRight               string
	PackageLicenseConcluded string
	PackageLicenseDeclared  string
	ExternalRefs            []GetExternalReference
	composition             map[string]string
}

func NewComponent() *Component {
	return &Component{}
}

func (c Component) GetPrimaryCompInfo() GetPrimaryComp {
	return c.PrimaryCompt
}

func (c Component) GetName() string {
	return c.Name
}

func (c Component) GetVersion() string {
	return c.Version
}

func (c Component) GetPurls() []purl.PURL {
	return c.Purls
}

func (c Component) GetCpes() []cpe.CPE {
	return c.Cpes
}

func (c Component) Swhids() []swhid.SWHID {
	return c.Swhid
}

func (c Component) Swids() []swid.SWID {
	return c.Swid
}

func (c Component) OmniborIDs() []omniborid.OMNIBORID {
	return c.OmniID
}

func (c Component) GetLicenses() []licenses.License {
	return c.Licenses
}

func (c Component) DeclaredLicenses() []licenses.License {
	return c.DeclaredLicense
}

func (c Component) ConcludedLicenses() []licenses.License {
	return c.ConcludedLicense
}

func (c Component) GetChecksums() []GetChecksum {
	return c.Checksums
}

func (c Component) PrimaryPurpose() string {
	return c.Purpose
}

func (c Component) RequiredFields() bool {
	return c.isReqFieldsPresent
}

func (c Component) GetID() string {
	return c.ID
}

func (c Component) Manufacturer() GetManufacturer {
	return c.manufacturer
}

func (c Component) Suppliers() GetSupplier {
	return c.Supplier
}

func (c Component) Authors() []GetAuthor {
	return c.Athrs
}

func (c Component) CountOfDependencies() int {
	return c.Count
}

func (c Component) Deps() []string {
	return c.Dep
}

func (c Component) GetSourceCodeURL() string {
	return c.SourceCodeURL
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
	return c.HasRelationships
}

func (c Component) RelationShipState() string {
	return c.RelationshipState
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

func (c Component) GetComposition(componentID string) string {
	return c.composition[componentID]
}
