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

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

//counterfeiter:generate . Document
type Document interface {
	Spec() Spec
	SchemaValidation() bool
	Components() []GetComponent
	Relations() []GetRelation
	Authors() []GetAuthor
	Tools() []GetTool
	Logs() []string

	Lifecycles() []string
	Manufacturer() GetManufacturer
	Supplier() GetSupplier

	PrimaryComp() GetPrimaryComp
	GetRelationships(string) []string

	Vulnerabilities() []GetVulnerabilities
	Signature() GetSignature
}
