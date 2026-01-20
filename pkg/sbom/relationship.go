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

type GetRelationship interface {
	GetFrom() string
	GetTo() string
	GetType() string
}

type Relationship struct {
	From string // component ID
	To   string // component ID
	Type string // relationship type
}

func (r Relationship) GetFrom() string {
	return r.From
}

func (r Relationship) GetTo() string {
	return r.To
}

func (r Relationship) GetType() string {
	return r.Type
}
