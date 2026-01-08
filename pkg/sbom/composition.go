// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

// CompositionScope defines *what aspect* of completeness is being declared.
// It indicates which dimension of the SBOM the composition applies to.
type CompositionScope string

const (
	// ScopeAssemblies applies to bundled / shaded components inside another component.
	ScopeAssemblies CompositionScope = "assemblies"

	// ScopeDependencies applies to the dependency graph of a component.
	ScopeDependencies CompositionScope = "dependencies"

	// ScopeVulnerabilities applies to vulnerability coverage completeness.
	ScopeVulnerabilities CompositionScope = "vulnerabilities"

	// ScopeGlobal applies to the entire SBOM.
	// This is a derived scope when no specific dimension is declared.
	ScopeGlobal CompositionScope = "global"
)

// CompositionAggregate defines the *declared level of completeness*
// for a given composition scope.
type CompositionAggregate string

const (
	// AggregateComplete indicates the producer asserts that
	// nothing relevant is missing for the given scope.
	AggregateComplete CompositionAggregate = "complete"

	// AggregateIncomplete indicates the producer knows that
	// some information is missing for the given scope.
	AggregateIncomplete CompositionAggregate = "incomplete"

	// AggregateUnknown indicates the producer cannot assert
	// whether the information is complete or not.
	AggregateUnknown CompositionAggregate = "unknown"

	// AggregateIncompleteFirstPartyOnly indicates completeness
	// is asserted only for first-party components, not third-party
	AggregateIncompleteFirstPartyOnly CompositionAggregate = "incomplete_first_party_only"
)

// GetComposition represents a producer-declared completeness assertion
// for a specific dimension of an SBOM.
type GetComposition interface {
	ID() string
	Aggregate() CompositionAggregate
	Scope() CompositionScope
	IsSBOMComplete() bool
	Dependencies() []string
	Assemblies() []string
	Vulnerabilities() []string
}

type Composition struct {
	id        string
	scope     CompositionScope
	aggregate CompositionAggregate

	// Targets (raw CycloneDX references)
	dependencies    []string
	assemblies      []string
	vulnerabilities []string
}

// ID returns the unique identifier of the composition itself.
// Ex. bom-ref
func (c Composition) ID() string {
	return c.id
}

// Aggregate returns the declared level of completeness.
func (c Composition) Aggregate() CompositionAggregate {
	return c.aggregate
}

// Scope returns the dimension this composition applies to
// (e.g. dependencies, assemblies, vulnerabilities, or global).
func (c Composition) Scope() CompositionScope {
	return c.scope
}

// IsSBOMComplete returns true if this composition explicitly
// declares the entire SBOM as complete.
func (c Composition) IsSBOMComplete() bool {
	return c.scope == ScopeGlobal &&
		c.aggregate == AggregateComplete
}

// Dependencies returns the component IDs whose dependency graphs
// are covered by this composition.
func (c Composition) Dependencies() []string {
	return c.dependencies
}

// Assemblies returns the component IDs whose internal assemblies
// (bundled or shaded components) are covered by this composition.
func (c Composition) Assemblies() []string {
	return c.assemblies
}

// Vulnerabilities returns the vulnerability IDs covered by
// this composition.
func (c Composition) Vulnerabilities() []string {
	return c.vulnerabilities
}

// NewComposition constructs a Composition instance.
func NewComposition(id string, scope CompositionScope, aggregate CompositionAggregate,
	deps []string, assemblies []string, vulns []string,
) Composition {
	return Composition{
		id:              id,
		scope:           scope,
		aggregate:       aggregate,
		dependencies:    deps,
		assemblies:      assemblies,
		vulnerabilities: vulns,
	}
}
