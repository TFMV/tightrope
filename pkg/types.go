package pkg

import (
	"fmt"
	"strings"
)

// Severity represents the severity of a finding.
type Severity string

const (
	Critical Severity = "Critical"
	Warning  Severity = "Warning"
	Info     Severity = "Info"
	Notice   Severity = "Notice"
)

// AuditRule represents a specific audit rule.
type AuditRule string

const (
	// RuleKeyConflict is a rule that checks for key conflicts.
	RuleKeyConflict AuditRule = "KeyConflict"
	// RuleRedundant is a rule that checks for redundant values.
	RuleRedundant AuditRule = "RedundantValue"
	// RuleDeprecated is a rule that checks for deprecated fields.
	RuleDeprecated AuditRule = "DeprecatedField"
	// RuleSecrets is a rule that checks for secrets in plain text.
	RuleSecrets AuditRule = "SecretInPlainText"
	// RuleShadowing is a rule that checks for key shadowing.
	RuleShadowing AuditRule = "KeyShadowing"
	// RuleCustom is a rule that checks for custom rule violations.
	RuleCustom AuditRule = "Custom"
	// RuleSuspiciousValue is a rule that checks for suspicious values.
	RuleSuspiciousValue AuditRule = "SuspiciousValue"
	// RuleHardcodedIP is a rule that checks for hardcoded IP addresses.
	RuleHardcodedIP AuditRule = "HardcodedIP"
	// RuleInsecureURL is a rule that checks for insecure URLs (HTTP instead of HTTPS).
	RuleInsecureURL AuditRule = "InsecureURL"
)

// ConfigData holds the parsed data and metadata of a configuration file.
type ConfigData struct {
	FilePath      string
	FileType      string
	FlattenedData map[string]interface{}
	Data          map[string]interface{}
	LineMap       map[string]int
}

// CustomRule defines a user-provided rule for the audit.
type CustomRule struct {
	Name     string   `yaml:"name"`
	Pattern  string   `yaml:"pattern"`
	Severity Severity `yaml:"severity"`
	Message  string   `yaml:"message"`
}

// SupportedExtensions lists the file extensions that are parsed.
var SupportedExtensions = []string{".yaml", ".yml", ".json", ".toml", ".tf", ".env", ".properties", ".ini", ".xml", "Dockerfile"}

// Format represents the output format for the audit report.
type Format string

const (
	// FormatMarkdown is for human-readable Markdown reports.
	FormatMarkdown Format = "markdown"
	// FormatJSON is for machine-readable JSON reports.
	FormatJSON Format = "json"
	// FormatHTML is for interactive HTML reports.
	FormatHTML Format = "html"
	// FormatDot is for graph-based DOT reports.
	FormatDot Format = "dot"
)

// IsValid checks if the format is a supported one.
func (f Format) IsValid() bool {
	switch f {
	case FormatMarkdown, FormatJSON, FormatHTML, FormatDot:
		return true
	default:
		return false
	}
}

// ToLower returns the lowercase string representation of the format.
func (f Format) ToLower() string {
	return strings.ToLower(string(f))
}

// String returns the string representation of the format.
func (f Format) String() string {
	return string(f)
}

// Set is used by command-line flag parsing to set the format.
func (f *Format) Set(value string) error {
	lowerVal := strings.ToLower(value)
	newFormat := Format(lowerVal)
	if !newFormat.IsValid() {
		return fmt.Errorf("invalid format: %s", value)
	}
	*f = newFormat
	return nil
}
