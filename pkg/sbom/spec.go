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
	Version() string
	FileFormat() string
	Parsable() bool
	Name() string
	SpecType() string
	RequiredFields() bool
	CreationTimestamp() string
	Licenses() []licenses.License
	Namespace() string
	URI() string
	Organization() string
	Comment() string
	SpdxID() string
}

type spec struct {
	version            string
	format             string
	specType           string
	name               string
	isReqFieldsPresent bool
	licenses           []licenses.License
	creationTimestamp  string
	namespace          string
	uri                string
	organization       string
	comment            string
	spdxid             string
}

func newSpec() *spec {
	return &spec{}
}

func (s spec) Organization() string {
	return s.organization
}

func (s spec) Comment() string {
	return s.comment
}

func (s spec) SpdxID() string {
	return s.spdxid
}

func (s spec) Version() string {
	return s.version
}

func (s spec) FileFormat() string {
	return s.format
}

func (s spec) Parsable() bool {
	return true
}

func (s spec) Name() string {
	return s.name
}

func (s spec) SpecType() string {
	return s.specType
}

func (s spec) RequiredFields() bool {
	return s.isReqFieldsPresent
}

func (s spec) CreationTimestamp() string {
	return s.creationTimestamp
}

func (s spec) Licenses() []licenses.License {
	return s.licenses
}

func (s spec) Namespace() string {
	return s.namespace
}

func (s spec) URI() string {
	return s.uri
}
