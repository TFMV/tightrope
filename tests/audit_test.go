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

			var keyConflictFindings int
			for _, f := range report.Findings {
				if f.Rule == pkg.RuleKeyConflict {
					keyConflictFindings++
				}
			}

			if keyConflictFindings != tt.expectedNumFindings {
				t.Errorf("Expected %d key conflict findings, got %d", tt.expectedNumFindings, keyConflictFindings)
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if finding.Rule == pkg.RuleKeyConflict && strings.Contains(finding.Message, expectedMessage) {
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
			expectedNumFindings: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			var secretFindings int
			for _, f := range report.Findings {
				if f.Rule == pkg.RuleSecrets {
					secretFindings++
				}
			}

			if secretFindings != tt.expectedNumFindings {
				t.Errorf("Expected %d secret findings, got %d", tt.expectedNumFindings, secretFindings)
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if finding.Rule == pkg.RuleSecrets && strings.Contains(finding.Message, expectedMessage) {
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

func TestAuditEngine_SuspiciousValue(t *testing.T) {
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
			name: "No suspicious values",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"database.host": "production-db.example.com",
						"database.port": 5432,
					},
				},
			},
			expectedNumFindings: 0,
		},
		{
			name: "Localhost detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"database.host": "localhost",
						"redis.host":    "127.0.0.1",
					},
				},
			},
			expectedMessages:    []string{"database.host", "redis.host"},
			expectedNumFindings: 2,
		},
		{
			name: "Plaintext password in value",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"connection_string": "password=mypassword",
					},
				},
			},
			expectedMessages:    []string{"connection_string"},
			expectedNumFindings: 1,
		},
		{
			name: "Admin credentials detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"auth": "admin:secretpass",
						"root": "root:password123",
					},
				},
			},
			expectedMessages:    []string{"auth", "root"},
			expectedNumFindings: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			var suspiciousFindings int
			for _, f := range report.Findings {
				if f.Rule == pkg.RuleSuspiciousValue {
					suspiciousFindings++
				}
			}

			if suspiciousFindings != tt.expectedNumFindings {
				t.Errorf("Expected %d suspicious value findings, got %d", tt.expectedNumFindings, suspiciousFindings)
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if finding.Rule == pkg.RuleSuspiciousValue && strings.Contains(finding.Message, expectedMessage) {
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

func TestAuditEngine_HardcodedIP(t *testing.T) {
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
			name: "No hardcoded IPs",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"database.host": "production-db.example.com",
					},
				},
			},
			expectedNumFindings: 0,
		},
		{
			name: "Hardcoded IP detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"server.address": "192.168.1.100",
						"debug.host":     "10.0.0.1",
					},
				},
			},
			expectedMessages:    []string{"server.address", "debug.host"},
			expectedNumFindings: 2,
		},
		{
			name: "Private IP range",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"internal.api": "172.16.0.1",
					},
				},
			},
			expectedMessages:    []string{"internal.api"},
			expectedNumFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			var ipFindings int
			var ipMessages []string
			for _, f := range report.Findings {
				if f.Rule == pkg.RuleHardcodedIP {
					ipFindings++
					ipMessages = append(ipMessages, f.Message)
				}
			}

			if ipFindings != tt.expectedNumFindings {
				t.Errorf("Expected %d hardcoded IP findings, got %d. Found: %v", tt.expectedNumFindings, ipFindings, ipMessages)
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if finding.Rule == pkg.RuleHardcodedIP && strings.Contains(finding.Message, expectedMessage) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find a finding with message containing '%s'. Found: %v", expectedMessage, ipMessages)
				}
			}
		})
	}
}

func TestAuditEngine_InsecureURL(t *testing.T) {
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
			name: "No insecure URLs",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"api.url": "https://api.example.com",
					},
				},
			},
			expectedNumFindings: 0,
		},
		{
			name: "HTTP URL detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"api.url":    "http://api.example.com",
						"legacy.url": "http://legacy.internal.com",
					},
				},
			},
			expectedMessages:    []string{"api.url", "legacy.url"},
			expectedNumFindings: 2,
		},
		{
			name: "localhost HTTP allowed",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"dev.url": "http://localhost:8080",
					},
				},
			},
			expectedNumFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			var urlFindings int
			var urlMessages []string
			for _, f := range report.Findings {
				if f.Rule == pkg.RuleInsecureURL {
					urlFindings++
					urlMessages = append(urlMessages, f.Message)
				}
			}

			if urlFindings != tt.expectedNumFindings {
				t.Errorf("Expected %d insecure URL findings, got %d. Found: %v", tt.expectedNumFindings, urlFindings, urlMessages)
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if finding.Rule == pkg.RuleInsecureURL && strings.Contains(finding.Message, expectedMessage) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find a finding with message containing '%s'. Found: %v", expectedMessage, urlMessages)
				}
			}
		})
	}
}

func TestAuditEngine_EnhancedSecrets(t *testing.T) {
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
			name: "AWS Access Key detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"aws.access_key": "AKIAIOSFODNN7EXAMPLE",
					},
				},
			},
			expectedMessages:    []string{"value of key 'aws.access_key'"},
			expectedNumFindings: 1,
		},
		{
			name: "Stripe key detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"secret": "sk-12345678901234567890ab",
					},
				},
			},
			expectedMessages:    []string{"key 'secret'"},
			expectedNumFindings: 1,
		},
		{
			name: "Database URL with credentials",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"database.url": "postgres://admin:secretpass@localhost:5432/mydb",
					},
				},
			},
			expectedMessages:    []string{"value of key 'database.url'"},
			expectedNumFindings: 1,
		},
		{
			name: "GitHub token detected",
			configs: []*pkg.ConfigData{
				{
					FilePath: "config.yaml",
					FlattenedData: map[string]interface{}{
						"github_token": "ghp_abcdefghijklmnopqrstuvwxyz123456",
					},
				},
			},
			expectedMessages:    []string{"key 'github_token'"},
			expectedNumFindings: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.AuditConfigs(tt.configs, ".")

			var secretFindings int
			var secretMessages []string
			for _, f := range report.Findings {
				if f.Rule == pkg.RuleSecrets {
					secretFindings++
					secretMessages = append(secretMessages, f.Message)
				}
			}

			if secretFindings != tt.expectedNumFindings {
				t.Errorf("Expected %d secret findings, got %d. Found: %v", tt.expectedNumFindings, secretFindings, secretMessages)
			}

			for _, expectedMessage := range tt.expectedMessages {
				found := false
				for _, finding := range report.Findings {
					if finding.Rule == pkg.RuleSecrets && strings.Contains(finding.Message, expectedMessage) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find a finding with message containing '%s'. Found: %v", expectedMessage, secretMessages)
				}
			}
		})
	}
}
