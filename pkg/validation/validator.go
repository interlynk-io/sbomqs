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

package validation

import (
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Validate validates a raw SBOM JSON Document against the official JSON schema
// for the given spec(CycloneDX or SPDX) and version
func Validate(spec string, version string, sbomBytes []byte) Result {
	// construct result
	result := Result{
		Valid: false,
		Logs:  []string{},
	}

	// 1. Resolve schema path
	result.Logs = append(result.Logs, fmt.Sprintf("resolving schema for spec=%q, version=%q", spec, version))

	schemaURL := schemaPath(spec, version)
	if schemaURL == "" {
		result.Logs = append(result.Logs, "no schema found for spec=%q, version=%q", spec, version)
		return result
	}

	result.Logs = append(result.Logs, fmt.Sprintf("resolved schema location: %s", schemaURL))

	// 2. Load & compile schema
	result.Logs = append(result.Logs, "loading and compiling JSON Schema")

	schema, err := loadSchema(schemaURL)
	if err != nil {
		result.Logs = append(result.Logs, "failed to load or compile schema: "+err.Error())
		return result
	}
	result.Logs = append(result.Logs, "schema loaded and compiled successfully")

	// 3. Decode SBOM JSON
	result.Logs = append(result.Logs, "decoding SBOM document JSON")

	var instance any
	if err := json.Unmarshal(sbomBytes, &instance); err != nil {
		result.Logs = append(result.Logs, "failed to decode SBOM JSON: "+err.Error())
		return result
	}
	result.Logs = append(result.Logs, "SBOM document decoded successfully")

	// 4. Validate SBOM JSON against official schema
	result.Logs = append(result.Logs, "validating SBOM document against compiled schema")

	err = schema.Validate(instance)
	if err == nil {
		result.Valid = true
		result.Logs = append(result.Logs, "SBOM document is valid according to the official JSON Schema")
		return result
	}

	// 5. Collect structured schema errors
	if ve, ok := err.(*jsonschema.ValidationError); ok {
		collectErrors(&result, ve, "")
	} else {
		result.Logs = append(result.Logs, err.Error())
	}

	return result
}

// collectErrors collect errors into human-readable error messages
func collectErrors(result *Result, e *jsonschema.ValidationError, path string) {
	loc := e.InstanceLocation
	if loc == "" {
		loc = path
	}

	if e.Message != "" {
		result.Logs = append(result.Logs, loc+": "+e.Message)
	}

	for _, c := range e.Causes {
		collectErrors(result, c, loc)
	}
}
