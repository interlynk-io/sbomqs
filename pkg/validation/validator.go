package validation

import (
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func Validate(spec string, version string, sbomBytes []byte) Result {

	// construct result
	result := Result{Valid: false}

	// 1. Resolve schema path
	schemaPath := schemaPath(spec, version)
	if schemaPath == "" {
		result.Errors = append(result.Errors, "schema not found for "+spec+" "+version)
		return result
	}
	fmt.Println("schemaPath: ", schemaPath)

	// 2. Load & compile schema
	schema, err := loadSchema(schemaPath)
	if err != nil {
		result.Errors = append(result.Errors, "failed to load schema: "+err.Error())
		return result
	}

	// 3. Decode SBOM JSON
	var instance any
	if err := json.Unmarshal(sbomBytes, &instance); err != nil {
		result.Errors = append(result.Errors, "invalid JSON: "+err.Error())
		return result
	}

	// 4. Validate SBOM JSON against official schema
	err = schema.Validate(instance)
	if err == nil {
		result.Valid = true
		return result
	}

	// 5. Collect structured schema errors
	if ve, ok := err.(*jsonschema.ValidationError); ok {
		collectErrors(&result, ve, "")
	} else {
		result.Errors = append(result.Errors, err.Error())
	}

	return result
}

// Recursively flatten validation errors
func collectErrors(result *Result, e *jsonschema.ValidationError, path string) {
	loc := e.InstanceLocation
	if loc == "" {
		loc = path
	}

	if e.Message != "" {
		result.Errors = append(result.Errors, loc+": "+e.Message)
	}

	for _, c := range e.Causes {
		collectErrors(result, c, loc)
	}
}
