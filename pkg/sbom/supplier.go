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

type GetSupplier interface {
	GetName() string
	GetEmail() string
	GetURL() string
	GetContacts() []Contact
	IsPresent() bool
}

type Supplier struct {
	Name     string
	Email    string
	URL      string
	Contacts []Contact
}

func (s Supplier) GetName() string {
	return s.Name
}

func (s Supplier) GetEmail() string {
	return s.Email
}

func (s Supplier) GetURL() string {
	return s.URL
}

func (s Supplier) GetContacts() []Contact {
	return s.Contacts
}

func (s Supplier) IsPresent() bool {
	return s.Name != "" || s.Email != "" || s.URL != "" || len(s.Contacts) > 0
}
