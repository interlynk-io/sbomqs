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

//counterfeiter:generate . Author
type GetAuthor interface {
	GetName() string
	GetType() string
	GetEmail() string
	GetPhone() string
}

type Author struct {
	Name       string
	Email      string
	AuthorType string // person or org
	Phone      string
}

func (a Author) GetName() string {
	return a.Name
}

func (a Author) GetType() string {
	return a.AuthorType
}

func (a Author) GetEmail() string {
	return a.Email
}

func (a Author) GetPhone() string {
	return a.Phone
}
