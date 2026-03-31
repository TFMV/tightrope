package audit

import (
	"os"
	"time"

	"github.com/TFMV/tightrope/internal/custom_rules"
	"github.com/TFMV/tightrope/internal/rules"
	"github.com/TFMV/tightrope/pkg"
	"github.com/rs/zerolog"
)

// Engine performs configuration auditing using a rule-based system.

type Engine struct {
	logger       zerolog.Logger
	ruleRegistry *rules.Registry
	customRules  []*custom_rules.CustomRule
}

// NewEngine creates a new audit engine and registers all available rules.
func NewEngine(customRules []*custom_rules.CustomRule) (*Engine, error) {
	registry := rules.NewRegistry()

	// Register all our new rules
	if err := registry.Register(&rules.KeyConflictsRule{}); err != nil {
		return nil, err
	}
	if err := registry.Register(&rules.ShadowingRule{}); err != nil {
		return nil, err
	}
	if err := registry.Register(&rules.SecretsInPlainRule{}); err != nil {
		return nil, err
	}
	if err := registry.Register(rules.NewDeprecatedFieldsRule()); err != nil {
		return nil, err
	}
	if err := registry.Register(&rules.SuspiciousValueRule{}); err != nil {
		return nil, err
	}
	if err := registry.Register(&rules.HardcodedIPRule{}); err != nil {
		return nil, err
	}
	if err := registry.Register(&rules.InsecureURLRule{}); err != nil {
		return nil, err
	}

	engine := &Engine{
		logger:       zerolog.New(os.Stderr).With().Timestamp().Logger(),
		ruleRegistry: registry,
		customRules:  customRules,
	}

	return engine, nil
}

// AuditConfigs audits multiple configuration files and returns a report.
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

	// Execute built-in rules
	allRules := e.ruleRegistry.GetRules()
	for _, rule := range allRules {
		findings, err := rule.Check(configs)
		if err != nil {
			e.logger.Error().Err(err).Str("rule", rule.Name()).Msg("Error executing rule")
			continue
		}

		report.Findings = append(report.Findings, findings...)
	}

	// Execute custom rules
	for _, customRule := range e.customRules {
		for _, config := range configs {
			for _, value := range config.FlattenedData {
				valueStr, ok := value.(string)
				if !ok {
					continue
				}

				if customRule.Match(valueStr) {
					finding := pkg.ReportEntry{
						Message:  customRule.Message,
						Rule:     pkg.RuleCustom,
						Severity: customRule.Severity,
					}
					report.Findings = append(report.Findings, finding)
				}
			}
		}
	}

	e.generateSummary(report)

	e.logger.Info().
		Int("total_findings", len(report.Findings)).
		Int("files_scanned", report.FilesScanned).
		Msg("Audit completed")

	return report
}

// generateSummary calculates the summary section of the audit report.
func (e *Engine) generateSummary(report *pkg.AuditReport) {
	report.Summary.TotalFindings = len(report.Findings)

	for _, finding := range report.Findings {
		report.Summary.FindingsBySeverity[finding.Severity]++
		report.Summary.FindingsByRule[finding.Rule]++
	}
}
