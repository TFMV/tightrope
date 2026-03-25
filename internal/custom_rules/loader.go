package custom_rules

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// LoadCustomRules loads custom rules from a YAML file.
func LoadCustomRules(filePath string) ([]*CustomRule, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var rules []*CustomRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, err
	}

	for _, rule := range rules {
		if err := rule.Compile(); err != nil {
			return nil, err
		}
	}

	return rules, nil
}
