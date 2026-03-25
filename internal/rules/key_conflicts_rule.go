package rules

import (
	"fmt"

	"github.com/TFMV/tightrope/internal/parser"
	"github.com/TFMV/tightrope/pkg"
)

// KeyConflictsRule checks for keys with different values across multiple files.
type KeyConflictsRule struct{}

// Name returns the name of the rule.
func (r *KeyConflictsRule) Name() string {
	return string(pkg.RuleKeyConflict)
}

// Check performs the audit and returns a list of findings.
func (r *KeyConflictsRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	keyValues := make(map[string]map[string][]string) // key -> value -> []filePaths

	for _, config := range configs {
		for key, value := range config.FlattenedData {
			valueStr := parser.GetStringValue(value)

			if _, ok := keyValues[key]; !ok {
				keyValues[key] = make(map[string][]string)
			}
			keyValues[key][valueStr] = append(keyValues[key][valueStr], config.FilePath)
		}
	}

	var findings []pkg.ReportEntry
	for key, values := range keyValues {
		if len(values) > 1 {
			var conflictingValues []string
			var firstFilePath string
			for value, filePaths := range values {
				if firstFilePath == "" && len(filePaths) > 0 {
					firstFilePath = filePaths[0]
				}
				for _, filePath := range filePaths {
					conflictingValues = append(conflictingValues, fmt.Sprintf("'%s' in %s", value, filePath))
				}
			}

			// Report one finding for the key conflict, associated with the first file found.
			if firstFilePath != "" {
				lineNumber := getLineNumber(configs, firstFilePath, key)
				findings = append(findings, pkg.ReportEntry{
					Message:  fmt.Sprintf("Key '%s' has conflicting values: %v", key, conflictingValues),
					Rule:     pkg.RuleKeyConflict,
					Severity: pkg.Warning,
					FilePath: firstFilePath,
					LineNumber: lineNumber,
				})
			}
		}
	}

	return findings, nil
}

// getLineNumber retrieves the line number for a given key in a specific file.
func getLineNumber(configs []*pkg.ConfigData, filePath, key string) int {
	for _, config := range configs {
		if config.FilePath == filePath {
			if line, ok := config.LineMap[key]; ok {
				return line
			}
		}
	}
	return 0 // Return 0 if not found
}
