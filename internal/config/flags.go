package config

import (
	"reflect"
	"strings"

	"github.com/spf13/pflag"
)

// fieldInfo stores information about a config field for flag registration
type fieldInfo struct {
	configPath string // e.g., "server.grpc_port"
	flagName   string // e.g., "server-grpc-port"
	usage      string // e.g., "gRPC server port (ext_authz, token exchange)"
	fieldType  reflect.Type
	fieldValue reflect.Value
}

// buildFlagMapping walks the Config struct recursively and builds a map
// from flag names to config paths using the koanf struct tags.
// Returns a map like: {"server-grpc-port": "server.grpc_port"}
func buildFlagMapping() (map[string]string, []fieldInfo) {
	var fields []fieldInfo
	mapping := make(map[string]string)

	walkStruct(reflect.TypeOf(Config{}), reflect.ValueOf(Config{}), "", &fields)

	for _, field := range fields {
		mapping[field.flagName] = field.configPath
	}

	return mapping, fields
}

// walkStruct recursively walks a struct and collects scalar fields
func walkStruct(t reflect.Type, v reflect.Value, parentPath string, fields *[]fieldInfo) {
	// Handle pointer types by getting the element type
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
		if v.IsValid() && !v.IsZero() {
			v = v.Elem()
		} else {
			v = reflect.New(t).Elem()
		}
	}

	if t.Kind() != reflect.Struct {
		return
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := reflect.Value{}
		if v.IsValid() {
			fieldValue = v.Field(i)
		}

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get the koanf tag
		koanfTag := field.Tag.Get("koanf")
		if koanfTag == "" || koanfTag == "-" {
			continue
		}

		// Handle squash tag (inline structs)
		if strings.Contains(koanfTag, "squash") {
			walkStruct(field.Type, fieldValue, parentPath, fields)
			continue
		}

		// Build the config path
		configPath := koanfTag
		if parentPath != "" {
			configPath = parentPath + "." + koanfTag
		}

		// Get the usage string from the usage tag
		usage := field.Tag.Get("usage")

		// Get the field type
		fieldType := field.Type

		// Handle different kinds of fields
		switch fieldType.Kind() {
		case reflect.Struct:
			// Recursively walk nested structs
			walkStruct(fieldType, fieldValue, configPath, fields)

		case reflect.Pointer:
			// Handle pointer to struct
			elemType := fieldType.Elem()
			if elemType.Kind() == reflect.Struct {
				walkStruct(elemType, reflect.Value{}, configPath, fields)
			} else if isScalarType(elemType) {
				// Pointer to scalar - treat as optional scalar
				flagName := configPathToFlagName(configPath)
				*fields = append(*fields, fieldInfo{
					configPath: configPath,
					flagName:   flagName,
					usage:      usage,
					fieldType:  elemType,
					fieldValue: fieldValue,
				})
			}

		case reflect.Slice, reflect.Map:
			// Skip slices and maps (too complex for command-line flags)
			continue

		default:
			// Scalar field - add to fields list
			if isScalarType(fieldType) {
				flagName := configPathToFlagName(configPath)
				*fields = append(*fields, fieldInfo{
					configPath: configPath,
					flagName:   flagName,
					usage:      usage,
					fieldType:  fieldType,
					fieldValue: fieldValue,
				})
			}
		}
	}
}

// isScalarType returns true if the type is a simple scalar (int, string, bool)
func isScalarType(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.String, reflect.Bool,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

// configPathToFlagName converts a config path to a flag name
// Examples:
//   - "server.grpc_port" -> "server-grpc-port"
//   - "trust_domain" -> "trust-domain"
func configPathToFlagName(configPath string) string {
	// Replace dots with hyphens
	flagName := strings.ReplaceAll(configPath, ".", "-")
	// Replace underscores with hyphens
	flagName = strings.ReplaceAll(flagName, "_", "-")
	return flagName
}

// RegisterFlags registers command-line flags for all scalar config fields
func RegisterFlags(flagSet *pflag.FlagSet) {
	mapping, fields := buildFlagMapping()

	for _, field := range fields {
		registerFlag(flagSet, field, mapping)
	}
}

// registerFlag registers a single flag based on its field info
func registerFlag(flagSet *pflag.FlagSet, field fieldInfo, mapping map[string]string) {
	// Check if flag already exists (avoid duplicate registration)
	if flagSet.Lookup(field.flagName) != nil {
		return
	}

	// Register based on type
	switch field.fieldType.Kind() {
	case reflect.String:
		flagSet.String(field.flagName, "", field.usage)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		flagSet.Int(field.flagName, 0, field.usage)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		flagSet.Uint(field.flagName, 0, field.usage)

	case reflect.Bool:
		flagSet.Bool(field.flagName, false, field.usage)

	case reflect.Float32, reflect.Float64:
		flagSet.Float64(field.flagName, 0.0, field.usage)
	}
}

// GetFlagMapping returns the mapping from flag names to config paths
// This is useful for the loader to know how to map flags to config keys
func GetFlagMapping() map[string]string {
	mapping, _ := buildFlagMapping()
	return mapping
}
