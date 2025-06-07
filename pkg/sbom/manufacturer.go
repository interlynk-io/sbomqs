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

//counterfeiter:generate . Manufacturer

type GetManufacturer interface {
	GetName() string
	GetURL() string
	GetEmail() string
	GetContacts() []Contact
}

type Manufacturer struct {
	Name     string
	URL      string
	Email    string
	Contacts []Contact
}

func (m Manufacturer) GetName() string {
	return m.Name
}

func (m Manufacturer) GetURL() string {
	return m.URL
}

func (m Manufacturer) GetEmail() string {
	return m.Email
}

func (m Manufacturer) GetContacts() []Contact {
	return m.Contacts
}
