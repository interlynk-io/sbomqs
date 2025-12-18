package validation

import (
	"encoding/json"
	"fmt"
)

func Validate(spec string, version string, sbomBytes []byte) Result {

	// constrcut result
	result := Result{
		Valid: false,
	}

	// 1. Resolve schema path
	schemaPath := schemaPath(spec, version)
	if schemaPath == "" {
		result.Errors = append(result.Errors, "schema not found for "+spec+" "+version)
		return result
	}
	fmt.Println("schemaPath: ", schemaPath)

	// 2. Load & compile schema (cached)
	schema, err := loadSchema(schemaPath)
	if err != nil {
		result.Errors = append(result.Errors, "failed to load schema: "+err.Error())
		return result
	}

	var instance any
	if err := json.Unmarshal(sbomBytes, &instance); err != nil {
		return result
	}

	// 3. Validate SBOM JSON against official schema
	err = schema.Validate(instance)
	if err == nil {
		result.Valid = true
		return result
	}

	// 4. Collect validation errors
	result.Errors = append(result.Errors, err.Error())

	return result
}
