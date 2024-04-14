// Copyright 2024 Interlynk.io
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

//counterfeiter:generate . Supplier

type Supplier interface {
	Name() string
	Email() string
	Url() string
	Contacts() []Contact
}

type supplier struct {
	name     string
	email    string
	url      string
	contacts []Contact
}

func (s supplier) Name() string {
	return s.name
}

func (s supplier) Email() string {
	return s.email
}

func (s supplier) Url() string {
	return s.url
}

func (s supplier) Contacts() []Contact {
	return s.contacts
}
