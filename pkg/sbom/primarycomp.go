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
	GetTotalNoOfDependencies() int
}

type PrimaryComp struct {
	Present         bool
	ID              string
	Dependecies     int
	hasDependencies bool
}

func (pc *PrimaryComp) IsPresent() bool {
	return pc.Present
}

func (pc *PrimaryComp) GetID() string {
	return pc.ID
}

func (pc *PrimaryComp) GetTotalNoOfDependencies() int {
	return pc.Dependecies
}

func (pc *PrimaryComp) HasDependencies() bool {
	return pc.hasDependencies
}
