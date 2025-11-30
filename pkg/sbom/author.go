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

//counterfeiter:generate . GetAuthor
// GetAuthor defines the interface for accessing author information in SBOMs
type GetAuthor interface {
	// GetName returns the name of the author
	GetName() string
	// GetType returns the type of author (person or organization)
	GetType() string
	// GetEmail returns the email address of the author
	GetEmail() string
	// GetPhone returns the phone number of the author
	GetPhone() string
}

// Author represents a concrete implementation of author information
type Author struct {
	Name       string
	Email      string
	AuthorType string // person or org
	Phone      string
}

// GetName returns the name of the author
func (a Author) GetName() string {
	return a.Name
}

// GetType returns the type of author (person or organization)
func (a Author) GetType() string {
	return a.AuthorType
}

// GetEmail returns the email address of the author
func (a Author) GetEmail() string {
	return a.Email
}

// GetPhone returns the phone number of the author
func (a Author) GetPhone() string {
	return a.Phone
}
