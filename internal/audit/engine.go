package audit

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/TFMV/tightrope/internal/parser"
	"github.com/TFMV/tightrope/pkg"
	"github.com/rs/zerolog"
)

//go:embed deprecated.json
var deprecatedFieldsData []byte

// Engine performs configuration auditing
type Engine struct {
	logger           zerolog.Logger
	deprecatedFields map[string][]string
	secretPatterns   []*regexp.Regexp
}

// NewEngine creates a new audit engine
func NewEngine() (*Engine, error) {
	engine := &Engine{
		logger: zerolog.New(os.Stderr).With().Timestamp().Logger(),
	}

	// Load deprecated fields
	if err := json.Unmarshal(deprecatedFieldsData, &engine.deprecatedFields); err != nil {
		return nil, fmt.Errorf("failed to load deprecated fields: %w", err)
	}

	// Initialize secret detection patterns
	engine.initSecretPatterns()

	return engine, nil
}

// initSecretPatterns initializes regex patterns for secret detection
func (e *Engine) initSecretPatterns() {
	patterns := []string{
		`(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?`,
		`(?i)(token|auth_token|bearer_token)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?`,
		`(?i)(api_key|apikey|key)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?`,
		`(?i)(secret|secret_key)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?`,
		`(?i)(access_key|private_key)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?`,
		`(?i)(oauth_token|jwt_secret)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?`,
		`(?i)(database_password|db_password)\s*[:=]\s*['\"]?[^'\"\s]+['\"]?`,
	}

	for _, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			e.secretPatterns = append(e.secretPatterns, regex)
		}
	}
}

// AuditConfigs audits multiple configuration files and returns a report
func (e *Engine) AuditConfigs(configs []*pkg.ConfigData, scanPath string) *pkg.AuditReport {
	report := &pkg.AuditReport{
		Timestamp:    time.Now(),
		ScanPath:     scanPath,
		FilesScanned: len(configs),
		Findings:     []pkg.ReportEntry{},
		Summary: pkg.ReportSummary{
			FindingsBySeverity: make(map[pkg.Severity]int),
			FindingsByRule:     make(map[pkg.AuditRule]int),
		},
	}

	// Run all audit rules
	e.checkKeyConflicts(configs, report)
	e.checkShadowing(configs, report)
	e.checkSecretsInPlain(configs, report)
	e.checkDeprecatedFields(configs, report)
	e.checkRedundantValues(configs, report)

	e.generateSummary(report)

	e.logger.Info().
		Int("total_findings", len(report.Findings)).
		Int("files_scanned", report.FilesScanned).
		Msg("Audit completed")

	return report
}

// checkKeyConflicts detects identical keys with different values across files
func (e *Engine) checkKeyConflicts(configs []*pkg.ConfigData, report *pkg.AuditReport) {
	keyValues := make(map[string]map[string][]string) // key -> value -> []filePaths

	for _, config := range configs {
		flattened := parser.FlattenMap(config.Data, "")
		for key, value := range flattened {
			valueStr := parser.GetStringValue(value)

			if keyValues[key] == nil {
				keyValues[key] = make(map[string][]string)
			}
			keyValues[key][valueStr] = append(keyValues[key][valueStr], config.FilePath)
		}
	}

	// Find conflicts
	for key, values := range keyValues {
		if len(values) > 1 {
			var conflictingFiles []string
			var conflictingValues []string

			for value, files := range values {
				conflictingValues = append(conflictingValues, value)
				conflictingFiles = append(conflictingFiles, files...)
			}

			for _, filePath := range conflictingFiles {
				lineNum := e.getLineNumber(configs, filePath, key)

				finding := pkg.ReportEntry{
					FilePath:       filePath,
					LineNumber:     lineNum,
					Rule:           pkg.RuleKeyConflict,
					Message:        fmt.Sprintf("Key '%s' has conflicting values across files: %v", key, conflictingValues),
					Recommendation: "Consolidate conflicting keys or use environment-specific configuration files",
					Severity:       pkg.SeverityWarning,
					Key:            key,
				}
				report.Findings = append(report.Findings, finding)
			}
		}
	}
}

// checkShadowing detects repeated keys in nested scopes within files
func (e *Engine) checkShadowing(configs []*pkg.ConfigData, report *pkg.AuditReport) {
	for _, config := range configs {
		e.findShadowingInMap(config.Data, "", config, report, make(map[string]bool))
	}
}

// findShadowingInMap recursively finds shadowed keys
func (e *Engine) findShadowingInMap(data map[string]interface{}, prefix string, config *pkg.ConfigData, report *pkg.AuditReport, seen map[string]bool) {
	for key, value := range data {
		currentKey := key
		if prefix != "" {
			currentKey = prefix + "." + key
		}

		// Check if we've seen this key before in the current scope
		if seen[key] {
			lineNum := e.getLineNumber([]*pkg.ConfigData{config}, config.FilePath, currentKey)

			finding := pkg.ReportEntry{
				FilePath:       config.FilePath,
				LineNumber:     lineNum,
				Rule:           pkg.RuleShadowing,
				Message:        fmt.Sprintf("Key '%s' shadows another key in the same scope", key),
				Recommendation: "Rename one of the conflicting keys to avoid shadowing",
				Severity:       pkg.SeverityWarning,
				Key:            currentKey,
			}
			report.Findings = append(report.Findings, finding)
		}

		seen[key] = true

		// Recursively check nested maps
		if nestedMap, ok := value.(map[string]interface{}); ok {
			nestedSeen := make(map[string]bool)
			e.findShadowingInMap(nestedMap, currentKey, config, report, nestedSeen)
		}
	}
}

// checkSecretsInPlain detects potential secrets in plain text
func (e *Engine) checkSecretsInPlain(configs []*pkg.ConfigData, report *pkg.AuditReport) {
	for _, config := range configs {
		flattened := parser.FlattenMap(config.Data, "")

		for key, value := range flattened {
			valueStr := parser.GetStringValue(value)

			// Skip if value is a placeholder
			if e.isSecretPlaceholder(valueStr) {
				continue
			}

			// Check if key looks like it contains secrets
			isSecretKey := e.isSecretKey(key)

			// Check if value matches secret patterns
			matchesPattern := false
			for _, pattern := range e.secretPatterns {
				if pattern.MatchString(fmt.Sprintf("%s: %s", key, valueStr)) {
					matchesPattern = true
					break
				}
			}

			// Only report if we found a secret (avoid duplicates)
			if isSecretKey || matchesPattern {
				lineNum := e.getLineNumber([]*pkg.ConfigData{config}, config.FilePath, key)

				var message string
				if isSecretKey {
					message = fmt.Sprintf("Potential secret in plain text: %s", key)
				} else {
					message = fmt.Sprintf("Pattern suggests secret in plain text: %s", key)
				}

				finding := pkg.ReportEntry{
					FilePath:       config.FilePath,
					LineNumber:     lineNum,
					Rule:           pkg.RuleSecretsInPlain,
					Message:        message,
					Recommendation: "Use environment variables, secret management systems, or encrypted storage",
					Severity:       pkg.SeverityCritical,
					Key:            key,
				}
				report.Findings = append(report.Findings, finding)
			}
		}
	}
}

// checkDeprecatedFields detects usage of deprecated configuration fields
func (e *Engine) checkDeprecatedFields(configs []*pkg.ConfigData, report *pkg.AuditReport) {
	for _, config := range configs {
		flattened := parser.FlattenMap(config.Data, "")

		for key, value := range flattened {
			// Check for deprecated keys
			if e.isDeprecatedField(key) {
				lineNum := e.getLineNumber([]*pkg.ConfigData{config}, config.FilePath, key)

				finding := pkg.ReportEntry{
					FilePath:       config.FilePath,
					LineNumber:     lineNum,
					Rule:           pkg.RuleDeprecated,
					Message:        fmt.Sprintf("Deprecated field detected: %s", key),
					Recommendation: "Update to use the recommended replacement field or remove if no longer needed",
					Severity:       pkg.SeverityWarning,
					Key:            key,
				}
				report.Findings = append(report.Findings, finding)
			}

			// Check for deprecated values (like API versions)
			if e.isDeprecatedValue(key, value) {
				lineNum := e.getLineNumber([]*pkg.ConfigData{config}, config.FilePath, key)

				finding := pkg.ReportEntry{
					FilePath:       config.FilePath,
					LineNumber:     lineNum,
					Rule:           pkg.RuleDeprecated,
					Message:        fmt.Sprintf("Deprecated field detected: %s", key),
					Recommendation: "Update to use the recommended replacement field or remove if no longer needed",
					Severity:       pkg.SeverityWarning,
					Key:            key,
				}
				report.Findings = append(report.Findings, finding)
			}
		}
	}
}

// checkRedundantValues detects identical key-value pairs across files
func (e *Engine) checkRedundantValues(configs []*pkg.ConfigData, report *pkg.AuditReport) {
	keyValueFiles := make(map[string]map[string][]string) // key-value -> []filePaths

	for _, config := range configs {
		flattened := parser.FlattenMap(config.Data, "")

		for key, value := range flattened {
			valueStr := parser.GetStringValue(value)
			keyValue := fmt.Sprintf("%s=%s", key, valueStr)

			if keyValueFiles[keyValue] == nil {
				keyValueFiles[keyValue] = make(map[string][]string)
			}
			keyValueFiles[keyValue]["files"] = append(keyValueFiles[keyValue]["files"], config.FilePath)
		}
	}

	// Find redundant values
	for keyValue, data := range keyValueFiles {
		files := data["files"]
		if len(files) > 1 {
			parts := strings.SplitN(keyValue, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]

			for _, filePath := range files {
				lineNum := e.getLineNumber(configs, filePath, key)

				finding := pkg.ReportEntry{
					FilePath:       filePath,
					LineNumber:     lineNum,
					Rule:           pkg.RuleRedundant,
					Message:        fmt.Sprintf("Redundant key-value pair '%s' found in multiple files", keyValue),
					Recommendation: "Consider consolidating common configurations into a shared file",
					Severity:       pkg.SeverityInfo,
					Key:            key,
					Value:          parts[1],
				}
				report.Findings = append(report.Findings, finding)
			}
		}
	}
}

// Helper functions

func (e *Engine) isSecretKey(key string) bool {
	lowerKey := strings.ToLower(key)
	secretKeywords := []string{
		"password", "passwd", "pwd", "secret", "token", "key", "api_key", "apikey",
		"private_key", "access_key", "secret_key", "auth_token", "bearer_token",
		"oauth_token", "jwt_secret", "database_password", "db_password",
	}

	for _, keyword := range secretKeywords {
		if strings.Contains(lowerKey, keyword) {
			return true
		}
	}
	return false
}

func (e *Engine) isSecretPlaceholder(value string) bool {
	placeholders := []string{
		"${", "{{", "ENV[", "<", "TODO", "FIXME", "***", "...",
	}

	for _, placeholder := range placeholders {
		if strings.Contains(value, placeholder) {
			return true
		}
	}

	// Check if it's obviously a placeholder (too short, common placeholder patterns)
	if len(value) < 8 && (value == "secret" || value == "password" || value == "token") {
		return true
	}

	return false
}

func (e *Engine) isDeprecatedField(key string) bool {
	for _, fields := range e.deprecatedFields {
		for _, field := range fields {
			// Check for exact key match
			if key == field {
				return true
			}
			// Check if the key contains the deprecated field
			if strings.Contains(key, field) {
				return true
			}
		}
	}
	return false
}

// Additional helper to check deprecated values
func (e *Engine) isDeprecatedValue(key string, value interface{}) bool {
	valueStr := parser.GetStringValue(value)

	// Check for deprecated API versions
	if key == "apiVersion" {
		deprecatedVersions := []string{
			"extensions/v1beta1",
			"apps/v1beta1",
			"apps/v1beta2",
		}
		for _, deprecated := range deprecatedVersions {
			if valueStr == deprecated {
				return true
			}
		}
	}

	return false
}

func (e *Engine) getLineNumber(configs []*pkg.ConfigData, filePath, key string) int {
	for _, config := range configs {
		if config.FilePath == filePath {
			if lineNum, exists := config.LineMap[key]; exists {
				return lineNum
			}
		}
	}
	return -1 // Unknown line number
}

func (e *Engine) generateSummary(report *pkg.AuditReport) {
	report.Summary.TotalFindings = len(report.Findings)

	for _, finding := range report.Findings {
		report.Summary.FindingsBySeverity[finding.Severity]++
		report.Summary.FindingsByRule[finding.Rule]++
	}
}
