// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package purl provides Package URL (PURL) parsing and validation functionality
// for handling package identifiers in SBOM documents.
package purl

import (
	pkg_purl "github.com/package-url/packageurl-go"
)

// PURL represents a Package URL that provides a universal way to identify
// and locate software packages across package managers and repositories.
type PURL string

// NewPURL creates a new PURL instance from the provided string.
// It does not perform validation; use Valid() method to check format compliance.
func NewPURL(prl string) PURL {
	return PURL(prl)
}

// Valid checks whether the PURL string conforms to the Package URL specification.
// It returns true if the PURL can be successfully parsed by the packageurl-go library.
func (p PURL) Valid() bool {
	_, err := pkg_purl.FromString(p.String())
	return err == nil
}

func (p PURL) String() string {
	return string(p)
}
