package rules

import (
	"fmt"
	"regexp"

	"github.com/TFMV/tightrope/pkg"
)

type HardcodedIPRule struct{}

func (r *HardcodedIPRule) Name() string {
	return string(pkg.RuleHardcodedIP)
}

func (r *HardcodedIPRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	var findings []pkg.ReportEntry

	ipPattern := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	for _, config := range configs {
		for key, value := range config.FlattenedData {
			valueStr := fmt.Sprintf("%v", value)
			if ipPattern.MatchString(valueStr) {
				findings = append(findings, pkg.ReportEntry{
					Message:    fmt.Sprintf("Hardcoded IP address found in key '%s'", key),
					Severity:   pkg.Warning,
					Rule:       pkg.RuleHardcodedIP,
					FilePath:   config.FilePath,
					LineNumber: getLineNumber(configs, config.FilePath, key),
				})
			}
		}
	}

	return findings, nil
}
