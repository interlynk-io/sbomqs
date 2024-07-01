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

import (
	"github.com/interlynk-io/sbomqs/pkg/licenses"
)

type Spec interface {
	GetVersion() string
	FileFormat() string
	Parsable() bool
	GetName() string
	GetSpecType() string
	RequiredFields() bool
	GetCreationTimestamp() string
	GetLicenses() []licenses.License
	GetNamespace() string
	URI() string
	GetOrganization() string
	GetComment() string
	GetSpdxID() string
}

type Specs struct {
	Version            string
	Format             string
	SpecType           string
	Name               string
	isReqFieldsPresent bool
	Licenses           []licenses.License
	CreationTimestamp  string
	Namespace          string
	uri                string
	Organization       string
	Comment            string
	Spdxid             string
}

func NewSpec() *Specs {
	return &Specs{}
}

func (s Specs) GetOrganization() string {
	return s.Organization
}

func (s Specs) GetComment() string {
	return s.Comment
}

func (s Specs) GetSpdxID() string {
	return s.Spdxid
}

func (s Specs) GetVersion() string {
	return s.Version
}

func (s Specs) FileFormat() string {
	return s.Format
}

func (s Specs) Parsable() bool {
	return true
}

func (s Specs) GetName() string {
	return s.Name
}

func (s Specs) GetSpecType() string {
	return s.SpecType
}

func (s Specs) RequiredFields() bool {
	return s.isReqFieldsPresent
}

func (s Specs) GetCreationTimestamp() string {
	return s.CreationTimestamp
}

func (s Specs) GetLicenses() []licenses.License {
	return s.Licenses
}

func (s Specs) GetNamespace() string {
	return s.Namespace
}

func (s Specs) URI() string {
	return s.uri
}
