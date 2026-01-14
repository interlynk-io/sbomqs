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

// Document defines the interface for accessing SBOM document information, components, and metadata
//
//counterfeiter:generate . Document
type Document interface {
	// Spec returns the SBOM specification information
	Spec() Spec
	// SchemaValidation returns whether the SBOM passes schema validation
	SchemaValidation() bool
	// Components returns all components defined in the SBOM
	Components() []GetComponent
	// Relations returns all relationships defined in the SBOM
	Relations() []GetRelation
	// Authors returns the authors of the SBOM
	Authors() []GetAuthor
	// Tools returns the tools used to create the SBOM
	Tools() []GetTool
	// Logs returns any log messages associated with the SBOM processing
	Logs() []string

	// Lifecycles returns the lifecycle phases represented in the SBOM
	Lifecycles() []string
	// Manufacturer returns the manufacturer information for the SBOM
	Manufacturer() GetManufacturer
	// Supplier returns the supplier information for the SBOM
	Supplier() GetSupplier

	// PrimaryComp returns information about the primary component in the SBOM
	PrimaryComp() GetPrimaryComponentInfo

	// // GetRelationships returns relationships for the specified component ID
	// GetRelationships(string) []string

	// Raw relationship graph
	GetRelationships() []GetRelationship

	// Graph navigation
	GetOutgoingRelations(compID string) []GetRelationship

	// Dependency helpers (semantic, but generic)
	GetDirectDependencies(compID string, relTypes ...string) []GetComponent
	// GetTransitiveDependencies(compID string, relTypes ...string) []Component

	// Vulnerabilities returns all vulnerabilities defined in the SBOM
	Vulnerabilities() []GetVulnerabilities
	// Signature returns the cryptographic signature information for the SBOM
	Signature() GetSignature

	Composition() []GetComposition
}

// kam->krodh->moh->lobh->ahnkar
