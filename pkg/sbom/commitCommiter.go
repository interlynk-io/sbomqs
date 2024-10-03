// Copyright 2024 Interlynk.io
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

type GetCommitCommitter interface {
	GetName() string
	GetEmail() string
	GetTimestamp() string
}

type CommitCommitter struct {
	Timestamp string `json:"date"`
	Name      string `json:"name"`
	Email     string `json:"email"`
}

func (cc CommitCommitter) GetName() string {
	return cc.Name
}

func (cc CommitCommitter) GetEmail() string {
	return cc.Email
}

func (cc CommitCommitter) GetTimestamp() string {
	return cc.Timestamp
}
