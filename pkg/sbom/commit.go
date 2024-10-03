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

type GetCommit interface {
	GetUID() string
	GetURL() string
	GetComitAuthor() CommitAuthor
	GetComitComiter() CommitCommitter
	GetMessage() string
}

// nolint
type Commit struct {
	Uid          string          `json:"sha"`
	Url          string          `json:"url"`
	ComitAuthor  CommitAuthor    `json:"author"`
	ComitComiter CommitCommitter `json:"committer"`
	Message      string          `json:"message"`
}

func (c Commit) GetUID() string {
	return c.Uid
}

func (c Commit) GetURL() string {
	return c.Url
}

func (c Commit) GetComitAuthor() CommitAuthor {
	return c.ComitAuthor
}

func (c Commit) GetComitComiter() CommitCommitter {
	return c.ComitComiter
}

func (c Commit) GetMessage() string {
	return c.Message
}
