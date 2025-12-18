package validation

import (
	"bytes"
	"embed"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
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

func loadSchema(schemaPath string) (*jsonschema.Schema, error) {
	if schemaPath == "" {
		return nil, fmt.Errorf("unknown schema kind: %s", schemaPath)
	}

	c := jsonschema.NewCompiler()
	if err := preloadSchemas(c); err != nil {
		return nil, err
	}

	// c.LoadURL = func(u string) (io.ReadCloser, error) {
	// 	// jsonschema passes file:// URLs
	// 	const prefix = "file://"
	// 	if strings.HasPrefix(u, prefix) {
	// 		path := strings.TrimPrefix(u, prefix)

	// 		// normalize to embedded FS path
	// 		if strings.Contains(path, "/pkg/validation/") {
	// 			idx := strings.Index(path, "/pkg/validation/")
	// 			path = path[idx+len("/pkg/validation/"):]
	// 		}

	// 		return schemaFS.Open(path)
	// 	}

	// 	return nil, fmt.Errorf("unknown schema: %s", u)
	// }

	// compiler is like: schema loader + resolver + linker
	sch, err := c.Compile(schemaPath)
	if err != nil {
		return nil, err
	}

	return sch, nil
}

var schemaRegistry = map[string]string{
	"http://cyclonedx.org/schema/spdx.schema.json":     "schemas/spdx/2.2.1/spdx-schema.json",
	"http://cyclonedx.org/schema/bom-1.5.schema.json":  "schemas/cyclonedx/1.5/bom-1.5.schema.json",
	"http://cyclonedx.org/schema/jsf-0.82.schema.json": "schemas/cyclonedx/1.5/jsf-0.82.schema.json",
}

func preloadSchemas(c *jsonschema.Compiler) error {
	for url, path := range schemaRegistry {
		data, err := schemaFS.ReadFile(path)
		if err != nil {
			return err
		}
		c.AddResource(url, bytes.NewReader(data))
	}
	return nil
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
