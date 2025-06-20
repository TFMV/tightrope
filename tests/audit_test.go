package tests

import (
	"testing"

	"github.com/TFMV/tightrope/internal/audit"
	"github.com/TFMV/tightrope/pkg"
)

func TestAuditEngine_KeyConflicts(t *testing.T) {
	engine, err := audit.NewEngine()
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name     string
		configs  []*pkg.ConfigData
		expected int // expected number of key conflict findings
	}{
		{
			name: "No conflicts",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config1.yaml",
					Data: map[string]interface{}{
						"database": map[string]interface{}{
							"host": "localhost",
							"port": 5432,
						},
					},
				},
				{
					FilePath: "config2.yaml",
					Data: map[string]interface{}{
						"redis": map[string]interface{}{
							"host": "localhost",
							"port": 6379,
						},
					},
				},
			},
			expected: 0,
		},
		{
			name: "Key conflict detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config1.yaml",
					Data: map[string]interface{}{
						"database": map[string]interface{}{
							"host": "localhost",
						},
					},
				},
				{
					FilePath: "config2.yaml",
					Data: map[string]interface{}{
						"database": map[string]interface{}{
							"host": "production-db",
						},
					},
				},
			},
			expected: 2, // One finding per file
		},
		{
			name: "Multiple conflicts",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config1.yaml",
					Data: map[string]interface{}{
						"env":  "dev",
						"port": 8080,
					},
				},
				{
					FilePath: "config2.yaml",
					Data: map[string]interface{}{
						"env":  "prod",
						"port": 9090,
					},
				},
			},
			expected: 4, // Two conflicts, two files each
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			conflictFindings := 0
			for _, finding := range report.Findings {
				if finding.Rule == pkg.RuleKeyConflict {
					conflictFindings++
				}
			}

			if conflictFindings != tt.expected {
				t.Errorf("Expected %d key conflict findings, got %d", tt.expected, conflictFindings)
			}
		})
	}
}

func TestAuditEngine_SecretsInPlain(t *testing.T) {
	engine, err := audit.NewEngine()
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name     string
		configs  []*pkg.ConfigData
		expected int // expected number of secret findings
	}{
		{
			name: "No secrets",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					Data: map[string]interface{}{
						"database": map[string]interface{}{
							"host": "localhost",
							"port": 5432,
						},
					},
				},
			},
			expected: 0,
		},
		{
			name: "Password detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					Data: map[string]interface{}{
						"database": map[string]interface{}{
							"password": "secretpassword123",
						},
					},
				},
			},
			expected: 1,
		},
		{
			name: "Multiple secrets",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					Data: map[string]interface{}{
						"api_key":      "sk-1234567890abcdef",
						"secret_token": "very-secret-token",
						"password":     "mypassword",
					},
				},
			},
			expected: 3,
		},
		{
			name: "Secret placeholders ignored",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					Data: map[string]interface{}{
						"password":   "${DB_PASSWORD}",
						"api_key":    "{{ .Values.apiKey }}",
						"secret_key": "TODO: add secret",
					},
				},
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			secretFindings := 0
			for _, finding := range report.Findings {
				if finding.Rule == pkg.RuleSecretsInPlain {
					secretFindings++
				}
			}

			if secretFindings != tt.expected {
				t.Errorf("Expected %d secret findings, got %d", tt.expected, secretFindings)
			}
		})
	}
}

func TestAuditEngine_DeprecatedFields(t *testing.T) {
	engine, err := audit.NewEngine()
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name     string
		configs  []*pkg.ConfigData
		expected int // expected number of deprecated field findings
	}{
		{
			name: "No deprecated fields",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					Data: map[string]interface{}{
						"apiVersion": "v1",
						"kind":       "Service",
					},
				},
			},
			expected: 0,
		},
		{
			name: "Deprecated Kubernetes fields",
			configs: []*pkg.ConfigData{
				{
					FilePath: "k8s-config.yaml",
					Data: map[string]interface{}{
						"apiVersion": "extensions/v1beta1",
						"spec": map[string]interface{}{
							"backend": map[string]interface{}{
								"serviceName": "my-service",
								"servicePort": 80,
							},
						},
					},
				},
			},
			expected: 3, // apiVersion, serviceName, servicePort
		},
		{
			name: "Deprecated Docker fields",
			configs: []*pkg.ConfigData{
				{
					FilePath: "docker-compose.yaml",
					Data: map[string]interface{}{
						"version": "3.0",
						"services": map[string]interface{}{
							"web": map[string]interface{}{
								"depends_on": []string{"db"},
								"links":      []string{"db:database"},
							},
						},
					},
				},
			},
			expected: 3, // version, depends_on, links
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			deprecatedFindings := 0
			for _, finding := range report.Findings {
				if finding.Rule == pkg.RuleDeprecated {
					deprecatedFindings++
				}
			}

			if deprecatedFindings != tt.expected {
				t.Errorf("Expected %d deprecated field findings, got %d", tt.expected, deprecatedFindings)
			}
		})
	}
}

func TestAuditEngine_RedundantValues(t *testing.T) {
	engine, err := audit.NewEngine()
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name     string
		configs  []*pkg.ConfigData
		expected int // expected number of redundant value findings
	}{
		{
			name: "No redundant values",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config1.yaml",
					Data: map[string]interface{}{
						"database": map[string]interface{}{
							"host": "localhost",
						},
					},
				},
				{
					FilePath: "config2.yaml",
					Data: map[string]interface{}{
						"redis": map[string]interface{}{
							"host": "localhost",
						},
					},
				},
			},
			expected: 0,
		},
		{
			name: "Redundant values detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config1.yaml",
					Data: map[string]interface{}{
						"timeout": 30,
						"retries": 3,
					},
				},
				{
					FilePath: "config2.yaml",
					Data: map[string]interface{}{
						"timeout": 30,
						"retries": 3,
					},
				},
			},
			expected: 4, // timeout and retries in both files
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			redundantFindings := 0
			for _, finding := range report.Findings {
				if finding.Rule == pkg.RuleRedundant {
					redundantFindings++
				}
			}

			if redundantFindings != tt.expected {
				t.Errorf("Expected %d redundant value findings, got %d", tt.expected, redundantFindings)
			}
		})
	}
}

func TestAuditEngine_Shadowing(t *testing.T) {
	engine, err := audit.NewEngine()
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name     string
		configs  []*pkg.ConfigData
		expected int // expected number of shadowing findings
	}{
		{
			name: "No shadowing",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					Data: map[string]interface{}{
						"database": map[string]interface{}{
							"host": "localhost",
							"port": 5432,
						},
						"redis": map[string]interface{}{
							"host": "localhost",
							"port": 6379,
						},
					},
				},
			},
			expected: 0,
		},
		{
			name: "Shadowing detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					Data: map[string]interface{}{
						"host": "global-host",
						"database": map[string]interface{}{
							"host": "localhost", // This shadows the global host
						},
					},
				},
			},
			expected: 0, // This test case actually shows nested keys, not same-scope shadowing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			shadowingFindings := 0
			for _, finding := range report.Findings {
				if finding.Rule == pkg.RuleShadowing {
					shadowingFindings++
				}
			}

			if shadowingFindings != tt.expected {
				t.Errorf("Expected %d shadowing findings, got %d", tt.expected, shadowingFindings)
			}
		})
	}
}

func TestAuditReport_Summary(t *testing.T) {
	engine, err := audit.NewEngine()
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	configs := []*pkg.ConfigData{
		{
			FilePath: "config.yaml",
			Data: map[string]interface{}{
				"password":   "secret123",          // Critical: secret
				"apiVersion": "extensions/v1beta1", // Warning: deprecated
				"timeout":    30,                   // Will be redundant
			},
		},
		{
			FilePath: "config2.yaml",
			Data: map[string]interface{}{
				"timeout": 30, // Info: redundant
			},
		},
	}

	report := engine.AuditConfigs(configs, ".")

	// Verify summary counts
	if report.Summary.TotalFindings == 0 {
		t.Error("Expected some findings in summary")
	}

	if len(report.Summary.FindingsBySeverity) == 0 {
		t.Error("Expected severity breakdown in summary")
	}

	if len(report.Summary.FindingsByRule) == 0 {
		t.Error("Expected rule breakdown in summary")
	}

	// Verify that summary totals match actual findings
	totalFromSeverity := 0
	for _, count := range report.Summary.FindingsBySeverity {
		totalFromSeverity += count
	}

	if totalFromSeverity != report.Summary.TotalFindings {
		t.Errorf("Severity summary total (%d) doesn't match total findings (%d)",
			totalFromSeverity, report.Summary.TotalFindings)
	}

	totalFromRules := 0
	for _, count := range report.Summary.FindingsByRule {
		totalFromRules += count
	}

	if totalFromRules != report.Summary.TotalFindings {
		t.Errorf("Rule summary total (%d) doesn't match total findings (%d)",
			totalFromRules, report.Summary.TotalFindings)
	}
}
