package custom_rules

import (
	"regexp"

	"github.com/TFMV/tightrope/pkg"
)

// CustomRule defines a user-configured rule.
type CustomRule struct {
	Name      string         `yaml:"name"`
	Pattern   string         `yaml:"pattern"`
	Severity  pkg.Severity   `yaml:"severity"`
	Message   string         `yaml:"message"`
	compiled  *regexp.Regexp // Compiled regex for efficiency
}

// Compile compiles the rule's regex pattern for efficient execution.
func (r *CustomRule) Compile() error {
	var err error
	r.compiled, err = regexp.Compile(r.Pattern)
	return err
}

// Match checks if the given text matches the rule's pattern.
func (r *CustomRule) Match(text string) bool {
	if r.compiled == nil {
		return false
	}
	return r.compiled.MatchString(text)
}
