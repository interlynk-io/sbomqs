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

//counterfeiter:generate . GetSupplier

// GetSupplier defines the interface for accessing supplier information in SBOMs
type GetSupplier interface {
	// GetName returns the name of the supplier
	GetName() string

	// GetEmail returns the email address of the supplier
	GetEmail() string

	// GetURL returns the website URL of the supplier
	GetURL() string

	// GetContacts returns the contact information for the supplier
	GetContacts() []Contact

	// IsAbsent returns whether supplier information is available
	IsAbsent() bool
}

// Supplier represents a concrete implementation of supplier information
type Supplier struct {
	Name     string
	Email    string
	URL      string
	Contacts []Contact
	Absent   bool
}

// GetName returns the name of the supplier
func (s Supplier) GetName() string {
	return s.Name
}

// GetEmail returns the email address of the supplier
func (s Supplier) GetEmail() string {
	return s.Email
}

// GetURL returns the website URL of the supplier
func (s Supplier) GetURL() string {
	return s.URL
}

// GetContacts returns the contact information for the supplier
func (s Supplier) GetContacts() []Contact {
	return s.Contacts
}

// IsAbsent returns whether supplier information is available
func (s Supplier) IsAbsent() bool {
	return s.Absent
}
