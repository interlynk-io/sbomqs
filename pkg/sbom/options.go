// Copyright 2025 Interlynk.io
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

import (
	"io"
)

// FormatVersionSPDX23 represents SPDX 2.3 version
const FormatVersionSPDX23 = FormatVersion("SPDX-2.3")

// NewSPDXDocWithOptions creates a new SPDX document with functional options
func NewSPDXDocWithOptions(f io.ReadSeeker, format FileFormat, version FormatVersion, opts ...SPDXOption) (Document, error) {
	return newSPDXDocWithOptions(f, format, version, opts...)
}

// NewCDXDocWithOptions creates a new CycloneDX document with functional options
func NewCDXDocWithOptions(f io.ReadSeeker, format FileFormat, opts ...CDXOption) (Document, error) {
	return newCDXDocWithOptions(f, format, opts...)
}