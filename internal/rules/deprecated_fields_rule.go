
package rules

import (
	"fmt"

	"github.com/TFMV/tightrope/pkg"
)

// DeprecatedFieldsRule checks for the use of deprecated fields.
type DeprecatedFieldsRule struct {
	deprecated map[string]string // a map of deprecated keys to their suggested replacements
}

// NewDeprecatedFieldsRule creates a new DeprecatedFieldsRule.
func NewDeprecatedFieldsRule() *DeprecatedFieldsRule {
	// In a real-world scenario, this map would be loaded from a configuration file.
	return &DeprecatedFieldsRule{
		deprecated: map[string]string{
			"apiVersion: extensions/v1beta1": "apiVersion: apps/v1",
		},
	}
}

// Name returns the name of the rule.
func (r *DeprecatedFieldsRule) Name() string {
	return string(pkg.RuleDeprecated)
}

// Check performs the audit and returns a list of findings.
func (r *DeprecatedFieldsRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	var findings []pkg.ReportEntry
	for _, config := range configs {
		for key, value := range config.Data {
			checkKey := fmt.Sprintf("%s: %v", key, value)
			if replacement, ok := r.deprecated[checkKey]; ok {
				findings = append(findings, pkg.ReportEntry{
					Message: fmt.Sprintf("Deprecated field '%s' used. Suggested replacement: '%s'", checkKey, replacement),
					Rule:     pkg.RuleDeprecated,
					Severity: pkg.Warning,
                    FilePath: config.FilePath,
                    LineNumber: config.LineMap[key],
				})
			}
		}
	}
	return findings, nil
}
