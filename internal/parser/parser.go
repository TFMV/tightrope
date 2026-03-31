package parser

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TFMV/tightrope/pkg"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

// Parser handles parsing of configuration files
type Parser struct {
	logger zerolog.Logger
}

// NewParser creates a new configuration parser
func NewParser() *Parser {
	return &Parser{
		logger: zerolog.New(os.Stderr).With().Timestamp().Logger(),
	}
}

// ParseFile parses a configuration file and returns normalized data
func (p *Parser) ParseFile(filePath string) (*pkg.ConfigData, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(filePath))

	if ext == "" {
		baseName := filepath.Base(filePath)
		if baseName == "Dockerfile" {
			ext = "Dockerfile"
		}
	}

	configData := &pkg.ConfigData{
		FilePath: filePath,
		FileType: ext,
		LineMap:  make(map[string]int),
	}

	switch ext {
	case ".yaml", ".yml":
		err = p.parseYAML(file, configData)
	case ".json":
		err = p.parseJSON(file, configData)
	case ".toml":
		err = p.parseTOML(file, configData)
	case ".env":
		err = p.parseEnv(file, configData)
	case ".properties":
		err = p.parseProperties(file, configData)
	case ".ini":
		err = p.parseINI(file, configData)
	case ".xml":
		err = p.parseXML(file, configData)
	case "Dockerfile":
		err = p.parseDockerfile(file, configData)
	default:
		return nil, fmt.Errorf("unsupported file format: %s", ext)
	}

	if err != nil {
		p.logger.Error().
			Err(err).
			Str("file", filePath).
			Str("format", ext).
			Msg("Failed to parse configuration file")
		return nil, err
	}

	// Flatten the data once after parsing
	configData.FlattenedData = FlattenMap(configData.Data, "")

	p.logger.Debug().
		Str("file", filePath).
		Str("format", ext).
		Int("keys", len(configData.Data)).
		Msg("Successfully parsed configuration file")

	return configData, nil
}

// parseYAML parses YAML content and extracts line numbers
func (p *Parser) parseYAML(reader io.Reader, configData *pkg.ConfigData) error {
	var yamlNode yaml.Node
	if err := yaml.NewDecoder(reader).Decode(&yamlNode); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Convert to map[string]interface{}
	var data map[string]interface{}
	if err := yamlNode.Decode(&data); err != nil {
		return fmt.Errorf("failed to decode YAML: %w", err)
	}

	configData.Data = data

	// Extract line numbers from YAML nodes
	if len(yamlNode.Content) > 0 {
		p.extractYAMLLines(yamlNode.Content[0], "", configData.LineMap)
	}

	return nil
}

// extractYAMLLines recursively extracts line numbers from YAML nodes
func (p *Parser) extractYAMLLines(node *yaml.Node, prefix string, lineMap map[string]int) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]

			key := keyNode.Value
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}

			lineMap[fullKey] = keyNode.Line

			// Recursively process nested objects
			if valueNode.Kind == yaml.MappingNode {
				p.extractYAMLLines(valueNode, fullKey, lineMap)
			}
		}
	}
}

// parseJSON parses JSON content
func (p *Parser) parseJSON(reader io.Reader, configData *pkg.ConfigData) error {
	var data map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	configData.Data = data

	// JSON doesn't provide line numbers easily, so we'll leave LineMap empty
	// In a production system, we might use a custom JSON parser that preserves line info

	return nil
}

// parseTOML parses TOML content
func (p *Parser) parseTOML(reader io.Reader, configData *pkg.ConfigData) error {
	var data map[string]interface{}
	if err := toml.NewDecoder(reader).Decode(&data); err != nil {
		return fmt.Errorf("failed to parse TOML: %w", err)
	}

	configData.Data = data

	// TODO:TOML doesn't provide line numbers easily with this library
	// In a production system, we might use a different TOML parser that preserves line info

	return nil
}

// parseEnv parses .env file content (KEY=VALUE format)
func (p *Parser) parseEnv(reader io.Reader, configData *pkg.ConfigData) error {
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read env file: %w", err)
	}

	data := make(map[string]interface{})
	lines := strings.Split(string(content), "\n")
	lineNum := 1

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			lineNum++
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			value = strings.Trim(value, `"`)
			value = strings.Trim(value, `'`)

			data[key] = value
			configData.LineMap[key] = lineNum
		}
		lineNum++
	}

	configData.Data = data
	return nil
}

// parseProperties parses Java properties file content
func (p *Parser) parseProperties(reader io.Reader, configData *pkg.ConfigData) error {
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read properties file: %w", err)
	}

	data := make(map[string]interface{})
	lines := strings.Split(string(content), "\n")
	lineNum := 1

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			lineNum++
			continue
		}

		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				data[key] = value
				configData.LineMap[key] = lineNum
			}
		}
		lineNum++
	}

	configData.Data = data
	return nil
}

// parseINI parses INI file content
func (p *Parser) parseINI(reader io.Reader, configData *pkg.ConfigData) error {
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read INI file: %w", err)
	}

	data := make(map[string]interface{})
	lines := strings.Split(string(content), "\n")
	currentSection := ""
	lineNum := 1

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			lineNum++
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			lineNum++
			continue
		}

		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				fullKey := key
				if currentSection != "" {
					fullKey = currentSection + "." + key
				}

				if _, exists := data[fullKey]; exists {
					lineMapKey := fmt.Sprintf("%s_2", fullKey)
					data[fullKey] = value
					configData.LineMap[lineMapKey] = lineNum
				} else {
					data[fullKey] = value
					configData.LineMap[fullKey] = lineNum
				}
			}
		}
		lineNum++
	}

	configData.Data = data
	return nil
}

// parseXML parses XML file content
func (p *Parser) parseXML(reader io.Reader, configData *pkg.ConfigData) error {
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read XML file: %w", err)
	}

	decoder := xml.NewDecoder(strings.NewReader(string(content)))
	data := make(map[string]interface{})

	type StackItem struct {
		prefix string
	}

	var stack []StackItem

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to parse XML: %w", err)
		}

		switch elem := token.(type) {
		case xml.StartElement:
			var newPrefix string
			if len(stack) == 0 {
				newPrefix = elem.Name.Local
			} else {
				newPrefix = stack[len(stack)-1].prefix + "." + elem.Name.Local
			}
			stack = append(stack, StackItem{prefix: newPrefix})

			for _, attr := range elem.Attr {
				key := newPrefix + "." + attr.Name.Local
				data[key] = attr.Value
			}

		case xml.CharData:
			text := strings.TrimSpace(string(elem))
			if text != "" && len(stack) > 0 {
				currentPrefix := stack[len(stack)-1].prefix
				data[currentPrefix] = text
			}

		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}

	configData.Data = data
	return nil
}

// parseDockerfile parses Dockerfile content
func (p *Parser) parseDockerfile(reader io.Reader, configData *pkg.ConfigData) error {
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read Dockerfile: %w", err)
	}

	data := make(map[string]interface{})
	lines := strings.Split(string(content), "\n")
	envVars := make(map[string]string)
	instructions := []string{}
	lineNum := 1

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			lineNum++
			continue
		}

		instructions = append(instructions, line)

		if strings.HasPrefix(strings.ToUpper(line), "ENV ") {
			rest := strings.TrimPrefix(line, "ENV ")
			parts := strings.SplitN(rest, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, `"`)
				envVars[key] = value
				data["env."+key] = value
				configData.LineMap["env."+key] = lineNum
			}
		}
		lineNum++
	}

	data["instructions"] = strings.Join(instructions, "\n")
	configData.Data = data

	return nil
}

// FlattenMap flattens a nested map using dot notation
func FlattenMap(data map[string]interface{}, prefix string) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		if nestedMap, ok := value.(map[string]interface{}); ok {
			// Recursively flatten nested maps
			nested := FlattenMap(nestedMap, fullKey)
			for k, v := range nested {
				result[k] = v
			}
		} else {
			result[fullKey] = value
		}
	}

	return result
}

// GetStringValue safely converts interface{} to string
func GetStringValue(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}
