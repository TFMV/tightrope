package tests

import (
	"strings"
	"testing"

	"github.com/TFMV/tightrope/internal/audit"
	"github.com/TFMV/tightrope/pkg"
)

func TestAuditEngine_KeyConflicts(t *testing.T) {
	engine, err := audit.NewEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name                string
		configs             []*pkg.ConfigData
		expectedMessages    []string
		expectedNumFindings int
	}{
		{
			name: "No conflicts",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config1.yaml",
					FlattenedData: map[string]interface{}{
						"database.host": "localhost",
						"database.port": 5432,
					},
				},
				{
					FilePath: "config2.yaml",
					FlattenedData: map[string]interface{}{
						"redis.host": "localhost",
						"redis.port": 6379,
					},
				},
			},
			expectedNumFindings: 0,
		},
		{
			name: "Key conflict detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config1.yaml",
					FlattenedData: map[string]interface{}{
						"database.host": "localhost",
					},
				},
				{
					FilePath: "config2.yaml",
					FlattenedData: map[string]interface{}{
						"database.host": "production-db",
					},
				},
			},
			expectedMessages:    []string{"Key 'database.host' has conflicting values"},
			expectedNumFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			if len(report.Findings) != tt.expectedNumFindings {
				t.Errorf("Expected %d key conflict findings, got %d", tt.expectedNumFindings, len(report.Findings))
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if strings.Contains(finding.Message, expectedMessage) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find a finding with message containing '%s'", expectedMessage)
				}
			}
		})
	}
}

func TestAuditEngine_SecretsInPlain(t *testing.T) {
	engine, err := audit.NewEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name                string
		configs             []*pkg.ConfigData
		expectedMessages    []string
		expectedNumFindings int
	}{
		{
			name: "No secrets",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"database.host": "localhost",
						"database.port": 5432,
					},
				},
			},
			expectedNumFindings: 0,
		},
		{
			name: "Password detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"database.password": "secretpassword123",
					},
				},
			},
			expectedMessages:    []string{"Potential secret found in key 'database.password'"},
			expectedNumFindings: 1,
		},
		{
			name: "Multiple secrets",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"api_key":      "sk-1234567890abcdef",
						"secret_token": "very-secret-token",
						"password":     "mypassword",
						"private_key":  "-----BEGIN PRIVATE KEY-----",
					},
				},
			},
			expectedMessages: []string{
				"Potential secret found in key 'api_key'",
				"Potential secret found in key 'secret_token'",
				"Potential secret found in key 'password'",
				"Potential secret found in key 'private_key'",
			},
			expectedNumFindings: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			if len(report.Findings) != tt.expectedNumFindings {
				t.Errorf("Expected %d secret findings, got %d", tt.expectedNumFindings, len(report.Findings))
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if strings.Contains(finding.Message, expectedMessage) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find a finding with message containing '%s'", expectedMessage)
				}
			}
		})
	}
}

func TestAuditEngine_DeprecatedFields(t *testing.T) {
	engine, err := audit.NewEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	tests := []struct {
		name                string
		configs             []*pkg.ConfigData
		expectedMessages    []string
		expectedNumFindings int
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
			expectedNumFindings: 0,
		},
		{
			name: "Deprecated Kubernetes fields",
			configs: []*pkg.ConfigData{
				{
					FilePath: "k8s-config.yaml",
					Data: map[string]interface{}{
						"apiVersion": "extensions/v1beta1",
					},
				},
			},
			expectedMessages:    []string{"Deprecated field 'apiVersion: extensions/v1beta1' used. Suggested replacement: 'apiVersion: apps/v1'"},
			expectedNumFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			if len(report.Findings) != tt.expectedNumFindings {
				t.Errorf("Expected %d deprecated field findings, got %d", tt.expectedNumFindings, len(report.Findings))
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if strings.Contains(finding.Message, expectedMessage) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find a finding with message containing '%s'", expectedMessage)
				}
			}
		})
	}
}

func TestAuditReport_Summary(t *testing.T) {
	engine, err := audit.NewEngine(nil)
	if err != nil {
		t.Fatalf("Failed to create audit engine: %v", err)
	}

	configs := []*pkg.ConfigData{
		{
			FilePath: "config.yaml",
			Data: map[string]interface{}{
				"password":   "secret123",          // Critical: secret
				"apiVersion": "extensions/v1beta1", // Warning: deprecated
			},
			FlattenedData: map[string]interface{}{
				"password":   "secret123",
				"apiVersion": "extensions/v1beta1",
			},
		},
		{
			FilePath: "config2.yaml",
			Data: map[string]interface{}{
				"timeout": 30,
			},
			FlattenedData: map[string]interface{}{
				"timeout": 30,
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
}
