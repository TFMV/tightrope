package pkg

import "time"

// Severity levels for audit findings
type Severity string

const (
	SeverityInfo     Severity = "Info"
	SeverityWarning  Severity = "Warning"
	SeverityCritical Severity = "Critical"
)

// AuditRule represents the type of audit rule violated
type AuditRule string

const (
	RuleKeyConflict    AuditRule = "Key Conflict"
	RuleShadowing      AuditRule = "Shadowing"
	RuleSecretsInPlain AuditRule = "Secrets in Plain Text"
	RuleDeprecated     AuditRule = "Deprecated Fields"
	RuleRedundant      AuditRule = "Redundant Values"
)

// ConfigData represents parsed configuration data
type ConfigData struct {
	FilePath string                 `json:"file_path"`
	Format   string                 `json:"format"`
	Data     map[string]interface{} `json:"data"`
	LineMap  map[string]int         `json:"line_map,omitempty"` // Maps keys to line numbers
}

// ReportEntry represents a single audit finding
type ReportEntry struct {
	FilePath       string    `json:"file_path"`
	LineNumber     int       `json:"line_number"`
	Rule           AuditRule `json:"rule"`
	Message        string    `json:"message"`
	Recommendation string    `json:"recommendation"`
	Severity       Severity  `json:"severity"`
	Key            string    `json:"key,omitempty"`
	Value          string    `json:"value,omitempty"`
}

// AuditReport contains all findings from an audit run
type AuditReport struct {
	Timestamp    time.Time     `json:"timestamp"`
	ScanPath     string        `json:"scan_path"`
	FilesScanned int           `json:"files_scanned"`
	Findings     []ReportEntry `json:"findings"`
	Summary      ReportSummary `json:"summary"`
}

// ReportSummary provides statistics about the audit
type ReportSummary struct {
	TotalFindings      int               `json:"total_findings"`
	FindingsBySeverity map[Severity]int  `json:"findings_by_severity"`
	FindingsByRule     map[AuditRule]int `json:"findings_by_rule"`
}

// AuditConfig holds configuration for the audit process
type AuditConfig struct {
	ScanPath       string
	OutputFormat   string
	IncludeSecrets bool
	CustomRules    []string
}

// FileExtensions supported by tightrope
var SupportedExtensions = []string{".yaml", ".yml", ".json", ".toml"}

// OutputFormats supported by tightrope
const (
	FormatMarkdown = "markdown"
	FormatJSON     = "json"
	FormatHTML     = "html"
)
