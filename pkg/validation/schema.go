package validation

import (
	"embed"
	"fmt"
	"io"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed schemas/cyclonedx/**
var schemaFS embed.FS

func schemaPath(spec, version string) string {
	switch spec {
	case "cyclonedx":
		return fmt.Sprintf("embedded://schemas/cyclonedx/%s/bom-%s.schema.json", version, version)
	default:
		return ""
	}
}

func loadSchema(schemaPath string) (*jsonschema.Schema, error) {
	if schemaPath == "" {
		return nil, fmt.Errorf("unknown schema kind: %s", schemaPath)
	}

	c := jsonschema.NewCompiler()

	// Teach compiler how to load embedded:// URLs
	c.LoadURL = func(url string) (io.ReadCloser, error) {
		const embeddedPrefix = "embedded://"

		// Case 1: embedded schema
		if strings.HasPrefix(url, embeddedPrefix) {
			path := strings.TrimPrefix(url, embeddedPrefix)
			return schemaFS.Open(path)
		}

		// Case 2: CycloneDX absolute schema URL
		if path, ok := mapSchemaURL(url); ok {
			return schemaFS.Open(path)
		}

		return nil, fmt.Errorf("unsupported schema url: %s", url)
	}

	// compiler is like: schema loader + resolver + linker
	schema, err := c.Compile(schemaPath)
	if err != nil {
		return nil, err
	}

	return schema, nil
}

func mapSchemaURL(url string) (string, bool) {
	switch url {
	case "http://cyclonedx.org/schema/spdx.schema.json":
		return "schemas/cyclonedx/common/spdx.schema.json", true
	case "http://cyclonedx.org/schema/license.schema.json":
		return "schemas/cyclonedx/common/license.schema.json", true
	// add more mappings as encountered
	default:
		return "", false
	}
}
