
package rules

import (
	"fmt"

	"github.com/TFMV/tightrope/pkg"
)

// ShadowingRule checks for keys that shadow other keys in the same scope.
type ShadowingRule struct{}

// Name returns the name of the rule.
func (r *ShadowingRule) Name() string {
	return string(pkg.RuleShadowing)
}

// Check performs the audit and returns a list of findings.
func (r *ShadowingRule) Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error) {
	var findings []pkg.ReportEntry
	for _, config := range configs {
		findings = append(findings, r.findShadowingInMap(config, config.Data, "", make(map[string]bool))...)
	}
	return findings, nil
}

func (r *ShadowingRule) findShadowingInMap(config *pkg.ConfigData, data map[string]interface{}, prefix string, seen map[string]bool) []pkg.ReportEntry {
	var findings []pkg.ReportEntry
	for key, value := range data {
		currentKey := key
		if prefix != "" {
			currentKey = prefix + "." + key
		}

		if seen[key] {
			findings = append(findings, pkg.ReportEntry{
				Message:    fmt.Sprintf("Key '%s' shadows another key in the same scope", key),
				Rule:       pkg.RuleShadowing,
				Severity:   pkg.Warning,
				FilePath:   config.FilePath,
				LineNumber: config.LineMap[currentKey],
			})
		}

		seen[key] = true

		if nestedMap, ok := value.(map[string]interface{}); ok {
			newSeen := make(map[string]bool)
			for k, v := range seen {
				newSeen[k] = v
			}
			findings = append(findings, r.findShadowingInMap(config, nestedMap, currentKey, newSeen)...)
		}
	}
	return findings
}
