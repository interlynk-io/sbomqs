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

//counterfeiter:generate . GetRelation
// GetRelation defines the interface for accessing SBOM relationship information between components
type GetRelation interface {
	// GetFrom returns the source component identifier in the relationship
	GetFrom() string
	// GetTo returns the target component identifier in the relationship
	GetTo() string
}

// Relation represents a concrete implementation of component relationships in an SBOM
type Relation struct {
	From string
	To   string
}

// GetFrom returns the source component identifier in the relationship
func (r Relation) GetFrom() string {
	return r.From
}

// GetTo returns the target component identifier in the relationship
func (r Relation) GetTo() string {
	return r.To
}
