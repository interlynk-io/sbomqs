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

//counterfeiter:generate . GetManufacturer

// GetManufacturer defines the interface for accessing manufacturer information in SBOMs
type GetManufacturer interface {
	// GetName returns the name of the manufacturer
	GetName() string
	// GetURL returns the website URL of the manufacturer
	GetURL() string
	// GetEmail returns the email address of the manufacturer
	GetEmail() string
	// GetContacts returns the contact information for the manufacturer
	GetContacts() []Contact
}

// Manufacturer represents a concrete implementation of manufacturer information
type Manufacturer struct {
	Name     string
	URL      string
	Email    string
	Contacts []Contact
}

// GetName returns the name of the manufacturer
func (m Manufacturer) GetName() string {
	return m.Name
}

// GetURL returns the website URL of the manufacturer
func (m Manufacturer) GetURL() string {
	return m.URL
}

// GetEmail returns the email address of the manufacturer
func (m Manufacturer) GetEmail() string {
	return m.Email
}

// GetContacts returns the contact information for the manufacturer
func (m Manufacturer) GetContacts() []Contact {
	return m.Contacts
}
