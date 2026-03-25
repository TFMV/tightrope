
package rules

import "fmt"

// Registry holds all the registered audit rules.
type Registry struct {
	rules map[string]Rule
}

// NewRegistry creates a new rule registry.
func NewRegistry() *Registry {
	return &Registry{
		rules: make(map[string]Rule),
	}
}

// Register adds a new rule to the registry.
func (r *Registry) Register(rule Rule) error {
	if _, exists := r.rules[rule.Name()]; exists {
		return fmt.Errorf("rule %q already registered", rule.Name())
	}
	r.rules[rule.Name()] = rule
	return nil
}

// GetRule returns a rule by its name.
func (r *Registry) GetRule(name string) (Rule, bool) {
	rule, ok := r.rules[name]
	return rule, ok
}

// GetRules returns all registered rules.
func (r *Registry) GetRules() []Rule {
	var allRules []Rule
	for _, rule := range r.rules {
		allRules = append(allRules, rule)
	}
	return allRules
}
