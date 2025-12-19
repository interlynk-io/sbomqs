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
		return fmt.Sprintf("pkg/validation/schemas/cyclonedx/%s/bom-%s.schema.json", version, version)
	default:
		return ""
	}
}

var schemaRegistry = map[string]string{
	// Common schemas
	"http://cyclonedx.org/schema/spdx.schema.json":     "schemas/cyclonedx/common/spdx.schema.json",
	"http://cyclonedx.org/schema/jsf-0.82.schema.json": "schemas/cyclonedx/common/jsf-0.82.schema.json",

	// Root schemas (add more versions as needed)
	"http://cyclonedx.org/schema/bom-1.2.schema.json": "schemas/cyclonedx/1.2/bom-1.2.schema.json",
	"http://cyclonedx.org/schema/bom-1.3.schema.json": "schemas/cyclonedx/1.3/bom-1.3.schema.json",
	"http://cyclonedx.org/schema/bom-1.4.schema.json": "schemas/cyclonedx/1.4/bom-1.4.schema.json",
	"http://cyclonedx.org/schema/bom-1.5.schema.json": "schemas/cyclonedx/1.5/bom-1.5.schema.json",
}

func loadSchema(schemaPath string) (*jsonschema.Schema, error) {
	if schemaPath == "" {
		return nil, fmt.Errorf("unknown schema path: %s", schemaPath)
	}

	c := jsonschema.NewCompiler()

	// 1. Preload all known schemas
	if err := preloadSchemas(c); err != nil {
		return nil, err
	}

	// 2. Compile root schema by embedded path
	return c.Compile(schemaPath)
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
