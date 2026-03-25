package pkg

import "time"

// AuditReport represents the final audit report.
type AuditReport struct {
	Timestamp    time.Time       `json:"timestamp"`
	ScanPath     string          `json:"scan_path"`
	FilesScanned int             `json:"files_scanned"`
	Findings     []ReportEntry   `json:"findings"`
	Summary      ReportSummary   `json:"summary"`
}

// ReportEntry represents a single finding in the audit report.
type ReportEntry struct {
	FilePath   string      `json:"file_path"`
	Rule       AuditRule   `json:"rule"`
	Message    string      `json:"message"`
	Severity   Severity    `json:"severity"`
	LineNumber int         `json:"line_number,omitempty"`
}

// ReportSummary provides a summary of the audit findings.
type ReportSummary struct {
	TotalFindings      int                  `json:"total_findings"`
	FindingsBySeverity map[Severity]int     `json:"findings_by_severity"`
	FindingsByRule     map[AuditRule]int    `json:"findings_by_rule"`
}
