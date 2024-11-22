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

type GetFile interface {
	GetFileName() string
	GetID() string
	GetChecksum() string
	GetAlgo() string
	GetFileType() []string
}

type File struct {
	Name     string
	ID       string
	Checksum string
	Algo     string
	FileType []string
}

func (f File) GetFileName() string {
	return f.Name
}

func (f File) GetID() string {
	return f.ID
}

func (f File) GetChecksum() string {
	return f.Checksum
}

func (f File) GetAlgo() string {
	return f.Algo
}

func (f File) GetFileType() []string {
	return f.FileType
}
