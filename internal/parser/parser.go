package parser

import (
	"encoding/json"
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

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	configData := &pkg.ConfigData{
		FilePath: filePath,
		Format:   ext,
		LineMap:  make(map[string]int),
	}

	switch ext {
	case ".yaml", ".yml":
		err = p.parseYAML(content, configData)
	case ".json":
		err = p.parseJSON(content, configData)
	case ".toml":
		err = p.parseTOML(content, configData)
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

	p.logger.Debug().
		Str("file", filePath).
		Str("format", ext).
		Int("keys", len(configData.Data)).
		Msg("Successfully parsed configuration file")

	return configData, nil
}

// parseYAML parses YAML content and extracts line numbers
func (p *Parser) parseYAML(content []byte, configData *pkg.ConfigData) error {
	var yamlNode yaml.Node
	if err := yaml.Unmarshal(content, &yamlNode); err != nil {
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
func (p *Parser) parseJSON(content []byte, configData *pkg.ConfigData) error {
	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	configData.Data = data

	// JSON doesn't provide line numbers easily, so we'll leave LineMap empty
	// In a production system, we might use a custom JSON parser that preserves line info

	return nil
}

// parseTOML parses TOML content
func (p *Parser) parseTOML(content []byte, configData *pkg.ConfigData) error {
	var data map[string]interface{}
	if err := toml.Unmarshal(content, &data); err != nil {
		return fmt.Errorf("failed to parse TOML: %w", err)
	}

	configData.Data = data

	// TODO:TOML doesn't provide line numbers easily with this library
	// In a production system, we might use a different TOML parser that preserves line info

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
