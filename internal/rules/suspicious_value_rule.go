package rules

import (
	"fmt"
	"regexp"

	"github.com/TFMV/tightrope/pkg"
)

type SuspiciousValueRule struct{}

func (r *SuspiciousValueRule) Name() string {
	return string(pkg.RuleSuspiciousValue)
}

func (r *SuspiciousValueRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	var findings []pkg.ReportEntry

	suspiciousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)`),
		regexp.MustCompile(`(?i)password\s*=\s*\w+`),
		regexp.MustCompile(`(?i)admin\s*:\s*\w+`),
		regexp.MustCompile(`(?i)root\s*:\s*\w+`),
		regexp.MustCompile(`(?i)test\s*:\s*\w+`),
		regexp.MustCompile(`(?i)dangerous|unsafe|vulnerable|exploit`),
		regexp.MustCompile(`(?i)eval\(|exec\(|system\(`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)<script>`),
	}

	for _, config := range configs {
		for key, value := range config.FlattenedData {
			valueStr := fmt.Sprintf("%v", value)
			for _, pattern := range suspiciousPatterns {
				if pattern.MatchString(valueStr) {
					findings = append(findings, pkg.ReportEntry{
						Message:    fmt.Sprintf("Suspicious value found in key '%s'", key),
						Severity:   pkg.Warning,
						Rule:       pkg.RuleSuspiciousValue,
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
