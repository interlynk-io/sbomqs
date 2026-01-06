// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

//counterfeiter:generate . GetPrimaryComp

// GetPrimaryComp defines the interface for accessing primary component information in SBOMs
type GetPrimaryComp interface {
	// IsPresent returns whether primary component information is available
	IsPresent() bool
	// GetID returns the unique identifier of the primary component
	GetID() string
	// GetName returns the name of the primary component
	GetName() string
	// GetType returns the type of the primary component
	GetType() string
	// GetVersion returns the version of the primary component
	GetVersion() string
	// GetTotalNoOfDependencies returns the total number of dependencies for the primary component
	GetTotalNoOfDependencies() int
	// HasDependencies returns whether the primary component has dependencies
	HasDependencies() bool
	// GetDependencies returns the list of dependency identifiers for the primary component
	GetDependencies() []string
}

// PrimaryComp represents a concrete implementation of primary component information
type PrimaryComp struct {
	Present         bool
	ID              string
	Type            string
	Dependecies     int
	HasDependency   bool
	Name            string
	Version         string
	AllDependencies []string
}

// IsPresent returns whether primary component information is available
func (pc PrimaryComp) IsPresent() bool {
	return pc.Present
}

// GetID returns the unique identifier of the primary component
func (pc PrimaryComp) GetID() string {
	return pc.ID
}

// GetName returns the name of the primary component
func (pc PrimaryComp) GetName() string {
	return pc.Name
}

// GetType returns the name of the primary component
func (pc PrimaryComp) GetType() string {
	return pc.Type
}

// GetVersion returns the version of the primary component
func (pc PrimaryComp) GetVersion() string {
	return pc.Version
}

// GetTotalNoOfDependencies returns the total number of dependencies for the primary component
func (pc PrimaryComp) GetTotalNoOfDependencies() int {
	return pc.Dependecies
}

// HasDependencies returns whether the primary component has dependencies
func (pc PrimaryComp) HasDependencies() bool {
	return pc.HasDependency
}

// GetDependencies returns the list of dependency identifiers for the primary component
func (pc PrimaryComp) GetDependencies() []string {
	return pc.AllDependencies
}
