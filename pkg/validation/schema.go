package validation

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas/**
var schemaFS embed.FS

func schemaPath(spec, version string) string {
	switch spec {
	case "cyclonedx":
		return fmt.Sprintf("http://cyclonedx.org/schema/bom-%s.schema.json", version)
		// return fmt.Sprintf("pkg/validation/schemas/cyclonedx/%s/bom-%s.schema.json", version, version)
	case "spdx":
		return fmt.Sprintf("spdx:%s", version)

		// return fmt.Sprintf("schemas/spdx/%s/spdx-schema.json", version)

	default:
		return ""
	}
}

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
