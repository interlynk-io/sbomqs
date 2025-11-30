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

// Package swid provides Software Identification (SWID) tag handling and validation
// functionality for processing SWID tags in SBOM documents.
package swid

// SWID represents a Software Identification tag interface that provides
// methods to access and validate SWID tag information for software components.
type SWID interface {
	GetName() string
	GetTagID() string
	Valid() bool
	String() string
}

type swid struct {
	TagID string
	Name  string
}

func (s swid) GetName() string {
	return s.Name
}

func (s swid) GetTagID() string {
	return s.TagID
}

func (s swid) Valid() bool {
	// Basic validation: check if the TagID is a non-empty string
	return s.TagID != ""
}

func (s swid) String() string {
	return s.TagID
}

// NewSWID creates a new SWID instance with the specified tag ID and name.
// The tag ID serves as the unique identifier for the software component.
func NewSWID(tagID, name string) SWID {
	return swid{
		TagID: tagID,
		Name:  name,
	}
}
