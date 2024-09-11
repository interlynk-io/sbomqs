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

package swid

type SWID interface {
	GetName() string
	GetTagID() string
	Valid() bool
	String() string
}

type swid struct {
	TagID string
	Name  string
}

func (s swid) GetName() string {
	return s.Name
}

func (s swid) GetTagID() string {
	return s.TagID
}

func (s swid) Valid() bool {
	// Basic validation: check if the TagID is a non-empty string
	return s.TagID != ""
}

func (s swid) String() string {
	return s.TagID
}

func NewSWID(tagID, name string) SWID {
	return swid{
		TagID: tagID,
		Name:  name,
	}
}
