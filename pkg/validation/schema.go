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
	"embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/**
var schemaFS embed.FS

// schemaPath returns the schema identifier which will be used to compil
// the JSON schema for a given SBOM spec and version
func schemaPath(spec, version string) string {
	switch spec {
	case "cyclonedx":
		return fmt.Sprintf("http://cyclonedx.org/schema/bom-%s.schema.json", version)
	case "spdx":
		return fmt.Sprintf("spdx:%s", version)
	default:
		return ""
	}
}

// schemaRegistry maps the schema identifiers to embedded schema file paths
var schemaRegistry = map[string]string{
	// Common schemas
	"http://cyclonedx.org/schema/spdx.schema.json":     "schemas/cyclonedx/common/spdx.schema.json",
	"http://cyclonedx.org/schema/jsf-0.82.schema.json": "schemas/cyclonedx/common/jsf-0.82.schema.json",

	// Root schemas
	"http://cyclonedx.org/schema/bom-1.2.schema.json": "schemas/cyclonedx/1.2/bom-1.2.schema.json",
	"http://cyclonedx.org/schema/bom-1.3.schema.json": "schemas/cyclonedx/1.3/bom-1.3.schema.json",
	"http://cyclonedx.org/schema/bom-1.4.schema.json": "schemas/cyclonedx/1.4/bom-1.4.schema.json",
	"http://cyclonedx.org/schema/bom-1.5.schema.json": "schemas/cyclonedx/1.5/bom-1.5.schema.json",
	"http://cyclonedx.org/schema/bom-1.6.schema.json": "schemas/cyclonedx/1.6/bom-1.6.schema.json",
	"http://cyclonedx.org/schema/bom-1.7.schema.json": "schemas/cyclonedx/1.7/bom-1.7.schema.json",

	// ---- SPDX ----
	"spdx:2.2.1": "schemas/spdx/2.2.1/spdx-schema.json",
	"spdx:2.2.2": "schemas/spdx/2.2.2/spdx-schema.json",
	"spdx:2.3":   "schemas/spdx/2.3/spdx-schema.json",
	"spdx:2.3.1": "schemas/spdx/2.3.1/spdx-schema.json",
}

// loadSchema compiles and returns a JSON schema
func loadSchema(schemaURL string) (*jsonschema.Schema, error) {
	if schemaURL == "" {
		return nil, fmt.Errorf("unknown schema")
	}

	c := jsonschema.NewCompiler()

	if err := preloadSchemas(c); err != nil {
		return nil, err
	}

	// Compile by canonical $id (URL)
	return c.Compile(schemaURL)
}

// preloadSchemas register all known JSON schemas with the compiler
/* NOTE: This step is required because jsonschema/v6 does not automatically
   load schemas from disk or fetch remote references. All schemas and
   their dependencies must be explicitly registered ahead of compilation.
*/
func preloadSchemas(c *jsonschema.Compiler) error {
	for uri, path := range schemaRegistry {
		data, err := schemaFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read schema %s: %w", path, err)
		}

		var schemaJSON any
		if err := json.Unmarshal(data, &schemaJSON); err != nil {
			return fmt.Errorf("parse schema %s: %w", path, err)
		}

		// v6 requires parsed JSON
		c.AddResource(uri, schemaJSON)
	}
	return nil
}
