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

type GetPrimaryComp interface {
	IsPresent() bool
	GetID() string
	GetName() string
	GetTotalNoOfDependencies() int
	HasDependencies() bool
	GetDependencies() []string
}

type PrimaryComp struct {
	Present         bool
	ID              string
	Dependecies     int
	HasDependency   bool
	Name            string
	AllDependencies []string
}

func (pc PrimaryComp) IsPresent() bool {
	return pc.Present
}

func (pc PrimaryComp) GetID() string {
	return pc.ID
}

func (pc PrimaryComp) GetName() string {
	return pc.Name
}

func (pc PrimaryComp) GetTotalNoOfDependencies() int {
	return pc.Dependecies
}

func (pc PrimaryComp) HasDependencies() bool {
	return pc.HasDependency
}

func (pc PrimaryComp) GetDependencies() []string {
	return pc.AllDependencies
}
