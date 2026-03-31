package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TFMV/tightrope/pkg"
)

type InsecureURLRule struct{}

func (r *InsecureURLRule) Name() string {
	return string(pkg.RuleInsecureURL)
}

func (r *InsecureURLRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	var findings []pkg.ReportEntry

	httpPattern := regexp.MustCompile(`http://`)

	for _, config := range configs {
		for key, value := range config.FlattenedData {
			valueStr := fmt.Sprintf("%v", value)
			if httpPattern.MatchString(valueStr) && !strings.Contains(valueStr, "localhost") && !strings.Contains(valueStr, "127.0.0.1") {
				findings = append(findings, pkg.ReportEntry{
					Message:    fmt.Sprintf("Insecure HTTP URL found in key '%s'", key),
					Severity:   pkg.Warning,
					Rule:       pkg.RuleInsecureURL,
					FilePath:   config.FilePath,
					LineNumber: getLineNumber(configs, config.FilePath, key),
				})
			}
		}
	}

	return findings, nil
}
