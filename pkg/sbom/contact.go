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

//counterfeiter:generate . GetContact

// GetContact defines the interface for accessing contact information in SBOMs
type GetContact interface {
	// GetName returns the name of the contact
	GetName() string
	// GetEmail returns the email address of the contact
	GetEmail() string
	// GetPhone returns the phone number of the contact
	GetPhone() string
}

// Contact represents a concrete implementation of contact information
type Contact struct {
	Name  string
	Email string
	Phone string
}

// GetName returns the name of the contact
func (c Contact) GetName() string {
	return c.Name
}

// GetEmail returns the email address of the contact
func (c Contact) GetEmail() string {
	return c.Email
}

// GetPhone returns the phone number of the contact
func (c Contact) GetPhone() string {
	return c.Phone
}
