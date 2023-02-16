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

import "github.com/interlynk-io/sbomqs/pkg/cpe"

//counterfeiter:generate . Component
type Component interface {
	ID() string
	SupplierName() string
	Name() string
	Version() string

	Purls() []string
	Cpes() []cpe.CPE

	Licenses() []License
	Checksums() []Checksum

	PrimaryPurpose() string
	RequiredFields() bool
}

type component struct {
	supplierName string
	name         string
	version      string

	purls []string
	cpes  []cpe.CPE

	licenses  []License
	checksums []Checksum

	purpose            string
	isReqFieldsPresent bool
	id                 string
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
func (c component) Purls() []string {
	return c.purls
}
func (c component) Cpes() []cpe.CPE {
	return c.cpes
}
func (c component) Licenses() []License {
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
