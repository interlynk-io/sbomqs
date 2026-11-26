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

// Package cpe provides CPE (Common Platform Enumeration) validation and handling
// functionality for parsing and validating CPE identifiers in SBOM documents.
package cpe

import (
	"strings"

	"github.com/knqyf263/go-cpe/naming"
)

// CPE represents a Common Platform Enumeration identifier used to uniquely
// identify classes of applications, operating systems, and hardware devices
// present in computing environments.
type CPE string

// Valid checks whether the CPE string conforms to the CPE specification format.
// It returns true if the CPE is a valid CPE 2.2 URI or CPE 2.3 formatted string.
// Uses github.com/knqyf263/go-cpe/naming for validation per NIST IR 7695.
func (cpe CPE) Valid() bool {
	s := strings.TrimSpace(cpe.String())
	if s == "" {
		return false
	}

	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "cpe:2.3:"):
		_, err := naming.UnbindFS(s)
		return err == nil
	case strings.HasPrefix(low, "cpe:/"):
		_, err := naming.UnbindURI(s)
		return err == nil
	default:
		return false
	}
}

// NewCPE creates a new CPE instance from the provided string.
// It does not perform validation; use Valid() method to check format compliance.
func NewCPE(cpe string) CPE {
	return CPE(cpe)
}

func (cpe CPE) String() string {
	return string(cpe)
}
