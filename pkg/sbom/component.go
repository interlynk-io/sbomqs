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

type Component interface {
	ID() string
	SupplierName() string
	Name() string
	Version() string
	Cpes() []cpe.CPE
	Purls() []purl.PURL
	Licenses() []licenses.License
	Checksums() []Checksum
	PrimaryPurpose() string
	RequiredFields() bool
	Supplier() Supplier
	Manufacturer() Manufacturer
	CountOfDependencies() int
	SourceCodeUrl() string
	DownloadLocationUrl() string
	SourceCodeHash() string
	IsPrimaryComponent() bool
	HasRelationShips() bool
	RelationShipState() string
	SpdxID() string
	FileAnalyzed() bool
	CopyRight() string
	PackageLicenseDeclared() string
	PackageLicenseConcluded() string
	ExternalReferences() []ExternalReference
}

type component struct {
	supplierName            string
	name                    string
	version                 string
	cpes                    []cpe.CPE
	purls                   []purl.PURL
	licenses                []licenses.License
	checksums               []Checksum
	purpose                 string
	isReqFieldsPresent      bool
	id                      string
	supplier                supplier
	manufacturer            manufacturer
	dependenciesCount       int
	sourceCodeUrl           string
	downloadLocation        string
	sourceCodeHash          string
	isPrimary               bool
	hasRelationships        bool
	relationshipState       string
	spdxid                  string
	fileAnalyzed            bool
	copyRight               string
	packageLicenseConcluded string
	packageLicenseDeclared  string
	externalReferences      []ExternalReference
}

func newComponent() *component {
	return &component{}
}

func (c component) SupplierName() string {
	return c.supplierName
}

func (c component) Name() string {
	return c.name
}

func (c component) Version() string {
	return c.version
}

func (c component) Purls() []purl.PURL {
	return c.purls
}

func (c component) Cpes() []cpe.CPE {
	return c.cpes
}

func (c component) Licenses() []licenses.License {
	return c.licenses
}

func (c component) Checksums() []Checksum {
	return c.checksums
}

func (c component) PrimaryPurpose() string {
	return c.purpose
}

func (c component) RequiredFields() bool {
	return c.isReqFieldsPresent
}

func (c component) ID() string {
	return c.id
}

func (c component) Manufacturer() Manufacturer {
	return c.manufacturer
}

func (c component) Supplier() Supplier {
	return c.supplier
}

func (c component) CountOfDependencies() int {
	return c.dependenciesCount
}

func (c component) SourceCodeUrl() string {
	return c.sourceCodeUrl
}

func (c component) DownloadLocationUrl() string {
	return c.downloadLocation
}

func (c component) SourceCodeHash() string {
	return c.sourceCodeHash
}

func (c component) IsPrimaryComponent() bool {
	return c.isPrimary
}

func (c component) HasRelationShips() bool {
	return c.hasRelationships
}

func (c component) RelationShipState() string {
	return c.relationshipState
}

func (c component) SpdxID() string {
	return c.spdxid
}

func (c component) FileAnalyzed() bool {
	return c.fileAnalyzed
}

func (c component) CopyRight() string {
	return c.copyRight
}

func (c component) PackageLicenseConcluded() string {
	return c.packageLicenseConcluded
}

func (c component) PackageLicenseDeclared() string {
	return c.packageLicenseDeclared
}

func (c component) ExternalReferences() []ExternalReference {
	return c.externalReferences
}
