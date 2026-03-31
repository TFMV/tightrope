package rules

import (
	"fmt"
	"regexp"

	"github.com/TFMV/tightrope/pkg"
)

// SecretsInPlainRule checks for secrets that are stored in plaintext.
type SecretsInPlainRule struct{}

var secretKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password|passwd|pwd`),
	regexp.MustCompile(`(?i)api_key|apikey`),
	regexp.MustCompile(`(?i)secret_key|secretkey`),
	regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)private_key|privatekey`),
}

var secretValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)sk-[a-z0-9]{20,}`),
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`(?i)gho_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`(?i)github_pat_[a-zA-Z0-9_]{22}`),
	regexp.MustCompile(`postgres://[^:]+:[^@]+@`),
	regexp.MustCompile(`mysql://[^:]+:[^@]+@`),
	regexp.MustCompile(`mongodb(\+srv)?://[^:]+:[^@]+@`),
	regexp.MustCompile(`redis://[^:]+:[^@]+@`),
	regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
}

// Name returns the name of the rule.
func (r *SecretsInPlainRule) Name() string {
	return string(pkg.RuleSecrets)
}

// Check performs the audit for secrets in plaintext.
func (r *SecretsInPlainRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	var findings []pkg.ReportEntry

	for _, config := range configs {
		for key, value := range config.FlattenedData {
			valueStr := fmt.Sprintf("%v", value)
			for _, pattern := range secretKeyPatterns {
				if pattern.MatchString(key) {
					findings = append(findings, pkg.ReportEntry{
						Message:    fmt.Sprintf("Potential secret found in key '%s'", key),
						Severity:   pkg.Critical,
						Rule:       pkg.RuleSecrets,
						FilePath:   config.FilePath,
						LineNumber: getLineNumber(configs, config.FilePath, key),
					})
					break
				}
			}
			for _, pattern := range secretValuePatterns {
				if pattern.MatchString(valueStr) {
					findings = append(findings, pkg.ReportEntry{
						Message:    fmt.Sprintf("Potential secret found in value of key '%s'", key),
						Severity:   pkg.Critical,
						Rule:       pkg.RuleSecrets,
						FilePath:   config.FilePath,
						LineNumber: getLineNumber(configs, config.FilePath, key),
					})
					break
				}
			}
		}
	}

	return findings, nil
}
