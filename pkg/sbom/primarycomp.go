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

type PrimaryComp interface {
	Present() bool
	ID() string
	Dependencies() int
}

type primaryComp struct {
	present     bool
	id          string
	dependecies int
}

func (pc *primaryComp) Present() bool {
	return pc.present
}

func (pc *primaryComp) ID() string {
	return pc.id
}

func (pc *primaryComp) Dependencies() int {
	return pc.dependecies
}
