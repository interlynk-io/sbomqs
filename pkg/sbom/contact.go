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

//counterfeiter:generate . Contact

type GetContact interface {
	GetName() string
	GetEmail() string
	GetPhone() string
}

type Contact struct {
	Name  string
	Email string
	Phone string
}

func (c Contact) GetName() string {
	return c.Name
}

func (c Contact) GetEmail() string {
	return c.Email
}

func (c Contact) GetPhone() string {
	return c.Phone
}
