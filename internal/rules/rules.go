
package rules

import (
	"github.com/TFMV/tightrope/pkg"
)

// Rule is the interface that all audit rules must implement.
type Rule interface {
	// Name returns the name of the rule.
	Name() string

	// Check performs the audit and returns a list of findings.
	Check(configs []*pkg.ConfigData) ([]pkg.ReportEntry, error)
}
