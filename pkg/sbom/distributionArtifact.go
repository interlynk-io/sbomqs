// Copyright 2026 Interlynk.io
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

// GetDistributionArtifact defines the interface for accessing a component's distribution artifact.
// A distribution artifact represents the deployable file (binary, archive, container, etc.)
// associated with a software component. In SPDX 3.0, this is the File element linked via
// hasDistributionArtifact relationship. In CycloneDX, this is represented via properties.
type GetDistributionArtifact interface {
	// GetFilename returns the filename of the distribution artifact
	GetFilename() string
	// IsExecutable returns whether the artifact is an executable
	IsExecutable() bool
	// IsArchive returns whether the artifact is an archive
	IsArchive() bool
	// IsStructured returns whether the artifact is structured (e.g., container)
	IsStructured() bool
	// GetHashes returns the cryptographic hashes of the artifact
	GetHashes() []GetChecksum
	// IsAbsent returns whether distribution artifact information is available
	IsAbsent() bool
}

// DistributionArtifact represents the concrete deployable file/artifact associated with a component.
type DistributionArtifact struct {
	Filename string
	IsExec   bool
	IsArch   bool
	IsStruct bool
	Hashes   []GetChecksum
	Absent   bool
}

// GetFilename returns the filename of the distribution artifact.
func (d DistributionArtifact) GetFilename() string {
	return d.Filename
}

// IsExecutable returns whether the artifact is an executable.
func (d DistributionArtifact) IsExecutable() bool {
	return d.IsExec
}

// IsArchive returns whether the artifact is an archive.
func (d DistributionArtifact) IsArchive() bool {
	return d.IsArch
}

// IsStructured returns whether the artifact is structured (e.g., container).
func (d DistributionArtifact) IsStructured() bool {
	return d.IsStruct
}

// GetHashes returns the cryptographic hashes of the artifact.
func (d DistributionArtifact) GetHashes() []GetChecksum {
	return d.Hashes
}

// IsAbsent returns whether distribution artifact information is available.
func (d DistributionArtifact) IsAbsent() bool {
	return d.Absent
}
