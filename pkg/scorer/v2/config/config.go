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

// Package config defines the configuration for sbomqs scoring.
// It lets callers choose which categories, features, and profiles to run,
// point to optional config files, and attach signature bundles. Higher-level
// code builds a Config and passes it to the scorer to shape how an SBOM
// should be evaluated.
package config

import (
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// Config represents the configuration parameters for SBOM scoring operations.
// It specifies which aspects of an SBOM to evaluate, including categories,
// features, and compliance profiles. The configuration can be used for both
// comprehensive scoring and profile-based compliance assessment.
type Config struct {
	// Categories specifies which comprehensive scoring categories to evaluate.
	// Examples include "provenance", "completeness", "structural", and "semantic".
	// If empty, all available categories will be evaluated.
	Categories []string

	// Features specifies which individual features to evaluate within categories.
	// Examples include "components", "dependencies", "licenses", and "vulnerabilities".
	// If empty, all available features within selected categories will be evaluated.
	Features []string

	// ConfigFile provides an optional path to a configuration file for additional
	// filtering and customization options. This is typically used for advanced
	// scoring configurations.
	ConfigFile string

	// Profile specifies which compliance profiles to evaluate the SBOM against.
	// Supported profiles include "ntia", "bsi-v1.1", "bsi-v2.0", "oct" (OpenChain Telco), etc.
	// Multiple profiles can be evaluated simultaneously.
	Profile []string

	// SignatureBundle contains cryptographic signature information for SBOM verification.
	// This includes the signature value, public key, and blob data for validation.
	SignatureBundle sbom.Signature

	// Recursive controls how directory paths are expanded when locating SBOM files.
	// When false (default), only files directly inside the specified directory are considered.
	// When true, sub-directories are walked recursively and all nested files are considered.
	Recursive bool
}
