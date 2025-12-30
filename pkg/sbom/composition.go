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

type CompositionScope string

const (
	ScopeAssemblies      CompositionScope = "assemblies"
	ScopeDependencies    CompositionScope = "dependencies"
	ScopeVulnerabilities CompositionScope = "vulnerabilities"

	// Internal / derived scope
	ScopeGlobal CompositionScope = "global"
)

type CompositionAggregate string

const (
	AggregateComplete                 CompositionAggregate = "complete"
	AggregateIncomplete               CompositionAggregate = "incomplete"
	AggregateUnknown                  CompositionAggregate = "unknown"
	AggregateIncompleteFirstPartyOnly CompositionAggregate = "incomplete_first_party_only"
)

type GetComposition interface {
	// Identity
	ID() string

	Aggregate() CompositionAggregate
	Scope() CompositionScope

	// IsSBOMComplete returns true if this composition
	// declares the entire SBOM as complete.
	IsSBOMComplete() bool

	Dependecies() []string

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

func (c Composition) ID() string {
	return c.id
}

func (c Composition) Scope() CompositionScope {
	return c.scope
}

func (c Composition) Aggregate() CompositionAggregate {
	return c.aggregate
}

func (c Composition) IsSBOMComplete() bool {
	return c.scope == ScopeGlobal &&
		c.aggregate == AggregateComplete
}

func (c Composition) Dependecies() []string {
	return c.dependencies
}

func (c Composition) Assemblies() []string {
	return c.assemblies
}

func (c Composition) Vulnerabilities() []string {
	return c.vulnerabilities
}
