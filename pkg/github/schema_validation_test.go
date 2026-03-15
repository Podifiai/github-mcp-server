package github

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOutputSchemaCoversAllStructFields validates that every tool's OutputSchema
// declares all JSON fields present in the actual Out type. This catches schema drift
// where the manually-defined OutputSchema omits fields that the Go struct serializes.
//
// The test uses reflection to walk the Out type's JSON tags and compares them against
// the OutputSchema properties (marshaled to map[string]any for SDK independence).
func TestOutputSchemaCoversAllStructFields(t *testing.T) {
	tools := AllTools(stubTranslation)
	require.NotEmpty(t, tools, "AllTools should return at least one tool")

	toolsChecked := 0
	for _, tool := range tools {
		// Only check tools that have both an OutType and an OutputSchema
		if tool.OutType == nil || tool.Tool.OutputSchema == nil {
			continue
		}

		t.Run(tool.Tool.Name, func(t *testing.T) {
			// Marshal OutputSchema to JSON and back to map for SDK-independent walking
			schemaBytes, err := json.Marshal(tool.Tool.OutputSchema)
			require.NoError(t, err, "failed to marshal OutputSchema")

			var schemaMap map[string]any
			require.NoError(t, json.Unmarshal(schemaBytes, &schemaMap), "failed to unmarshal OutputSchema to map")

			outType := tool.OutType
			// Dereference pointer types
			if outType.Kind() == reflect.Pointer {
				outType = outType.Elem()
			}

			assertSchemaCoversType(t, schemaMap, outType, "")
		})
		toolsChecked++
	}

	// Sanity check: ensure we actually checked some tools
	assert.Greater(t, toolsChecked, 0, "expected at least one tool with OutType and OutputSchema")
}

// assertSchemaCoversType recursively checks that the JSON Schema (as a map) contains
// properties for every JSON-tagged field on the given Go type.
func assertSchemaCoversType(t *testing.T, schema map[string]any, goType reflect.Type, path string) {
	t.Helper()

	// Dereference pointers
	for goType.Kind() == reflect.Pointer {
		goType = goType.Elem()
	}

	// Only structs have fields to validate
	if goType.Kind() != reflect.Struct {
		return
	}

	propsRaw, ok := schema["properties"]
	if !ok {
		// Schema has no properties defined but the Go type is a struct with fields.
		// This is acceptable for types declared as just {"type": "object"} (e.g. map-like).
		return
	}
	props, ok := propsRaw.(map[string]any)
	if !ok {
		return
	}

	for i := range goType.NumField() {
		field := goType.Field(i)

		// Handle embedded (anonymous) structs by recursing into their fields
		if field.Anonymous {
			assertSchemaCoversType(t, schema, field.Type, path)
			continue
		}

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		jsonName := jsonFieldName(field)
		if jsonName == "" || jsonName == "-" {
			continue
		}

		fieldPath := jsonName
		if path != "" {
			fieldPath = path + "." + jsonName
		}

		fieldType := derefType(field.Type)

		// Skip untyped fields (map[string]any, any/interface{}) — can't validate structure
		if isUntypedField(fieldType) {
			continue
		}

		propRaw, exists := props[jsonName]
		if !assert.True(t, exists, "OutputSchema missing property %q (Go field: %s)", fieldPath, field.Name) {
			continue
		}

		// If the property exists in the schema, recurse into nested types
		propMap, ok := propRaw.(map[string]any)
		if !ok {
			continue
		}

		// Recurse based on the Go field's kind
		switch fieldType.Kind() {
		case reflect.Struct:
			assertSchemaCoversType(t, propMap, fieldType, fieldPath)

		case reflect.Slice, reflect.Array:
			elemType := derefType(fieldType.Elem())
			if elemType.Kind() == reflect.Struct && !isUntypedField(elemType) {
				if items, ok := propMap["items"].(map[string]any); ok {
					assertSchemaCoversType(t, items, elemType, fieldPath+"[]")
				}
			}
		}
	}
}

// jsonFieldName extracts the JSON field name from a struct field's json tag.
// Returns "" if there is no json tag, or "-" if the field is explicitly excluded.
func jsonFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" {
		return ""
	}
	name, _, _ := strings.Cut(tag, ",")
	return name
}

// derefType dereferences pointer types to get the underlying type.
func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// isUntypedField returns true if the type is unstructured and can't be validated
// against a JSON Schema (e.g. map[string]any, any, interface{}).
func isUntypedField(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Interface:
		return true
	case reflect.Map:
		return true
	default:
		return false
	}
}
