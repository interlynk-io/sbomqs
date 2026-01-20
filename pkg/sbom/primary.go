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

type GetPrimaryComponentInfo interface {
	// GetID returns the unique identifier of the primary component
	GetID() string

	// GetName returns the name of the primary component
	GetName() string

	// GetVersion returns the version of the primary component
	GetVersion() string

	// GetType returns the type of the primary component
	GetType() string

	// IsPresent returns whether primary component information is available
	IsPresent() bool
}

// PrimaryComp represents a concrete implementation of primary component information
type PrimaryComponentInfo struct {
	ID      string
	Name    string
	Version string
	Type    string
	Present bool
}

// GetID returns the unique identifier of the primary component
func (pc PrimaryComponentInfo) GetID() string {
	return pc.ID
}

// GetName returns the name of the primary component
func (pc PrimaryComponentInfo) GetName() string {
	return pc.Name
}

// GetVersion returns the version of the primary component
func (pc PrimaryComponentInfo) GetVersion() string {
	return pc.Version
}

// GetType returns the name of the primary component
func (pc PrimaryComponentInfo) GetType() string {
	return pc.Type
}

// IsPresent returns whether primary component information is available
func (pc PrimaryComponentInfo) IsPresent() bool {
	return pc.Present
}
