package tests

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/TFMV/tightrope/internal/audit"
	"github.com/TFMV/tightrope/internal/custom_rules"
	"github.com/TFMV/tightrope/pkg"
)

func TestCustomRules(t *testing.T) {
	// Create a dummy .tightrope.yaml file
	customRulesContent := `
- name: "No foobar allowed"
  pattern: "foobar"
  severity: "Critical"
  message: "The value foobar is not allowed."
`
	if err := ioutil.WriteFile(".tightrope.yaml", []byte(customRulesContent), 0644); err != nil {
		t.Fatalf("Failed to create .tightrope.yaml: %v", err)
	}
	defer os.Remove(".tightrope.yaml")

	// Load custom rules
	customRules, err := custom_rules.LoadCustomRules(".tightrope.yaml")
	if err != nil {
		t.Fatalf("Failed to load custom rules: %v", err)
	}

	// Create a config with a value that should be caught by the custom rule
	configs := []*pkg.ConfigData{
		{
			FilePath: "config.yaml",
			FlattenedData: map[string]interface{}{
				"some_key": "this is foobar",
			},
		},
	}

	// Create an audit engine with the custom rules
	engine, err := audit.NewEngine(customRules)
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	// Run the audit
	report := engine.AuditConfigs(configs, ".")

	// Check for the custom rule finding
	if len(report.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(report.Findings))
	}

	finding := report.Findings[0]
	if finding.Rule != pkg.RuleCustom {
		t.Errorf("Expected finding to be of type Custom, got %s", finding.Rule)
	}

	if finding.Message != "The value foobar is not allowed." {
		t.Errorf("Unexpected finding message: %s", finding.Message)
	}
}
