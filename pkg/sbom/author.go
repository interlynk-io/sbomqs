// Copyright 2023 Interlynk.io
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
type Author interface {
	Name() string
	Type() string
	Email() string
}

type author struct {
	name       string
	email      string
	authorType string //person or org
}

func (a author) Name() string {
	return a.name
}
func (a author) Type() string {
	return a.authorType
}

func (a author) Email() string {
	return a.email
}
