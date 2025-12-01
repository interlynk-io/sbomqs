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

// Package swhid provides Software Heritage Identifier (SWHID) validation and handling
// functionality for processing persistent identifiers in SBOM documents.
package swhid

import "regexp"

// SWHID represents a Software Heritage Identifier that provides persistent
// identifiers for software artifacts stored in the Software Heritage archive.
type SWHID string

const swhidRegex = `^swh:1:cnt:[a-fA-F0-9]{40}$`

// Valid checks whether the SWHID string conforms to the Software Heritage
// identifier specification format (swh:1:cnt:<sha1_hash>).
func (swhid SWHID) Valid() bool {
	return regexp.MustCompile(swhidRegex).MatchString(swhid.String())
}

// NewSWHID creates a new SWHID instance from the provided string.
// It does not perform validation; use Valid() method to check format compliance.
func NewSWHID(swhid string) SWHID {
	return SWHID(swhid)
}

func (swhid SWHID) String() string {
	return string(swhid)
}
