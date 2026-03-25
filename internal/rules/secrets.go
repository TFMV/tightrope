package rules

import (
	"fmt"
	"regexp"

	"github.com/TFMV/tightrope/pkg"
)

// SecretsInPlainRule checks for secrets that are stored in plaintext.
type SecretsInPlainRule struct{}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password|passwd|pwd`),
	regexp.MustCompile(`(?i)api_key|apikey`),
	regexp.MustCompile(`(?i)secret_key|secretkey`),
	regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)private_key|privatekey`),
}

// Name returns the name of the rule.
func (r *SecretsInPlainRule) Name() string {
	return string(pkg.RuleSecrets)
}

// Check performs the audit for secrets in plaintext.
func (r *SecretsInPlainRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	var findings []pkg.ReportEntry

	for _, config := range configs {
		for key, lineNumber := range config.LineMap {
			for _, pattern := range secretPatterns {
				if pattern.MatchString(key) {
					findings = append(findings, pkg.ReportEntry{
						Message:    fmt.Sprintf("Potential secret found in key '%s'", key),
						Severity:   pkg.Critical,
						Rule:       pkg.RuleSecrets,
						FilePath:   config.FilePath,
						LineNumber: lineNumber,
					})
				}
			}
		}
	}

	return findings, nil
}
