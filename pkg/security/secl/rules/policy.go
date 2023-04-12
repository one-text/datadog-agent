// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package rules

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"io"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/security/secl/validators"
	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v2"
)

// PolicyDef represents a policy file definition
type PolicyDef struct {
	Version string             `yaml:"version"`
	Rules   []*RuleDefinition  `yaml:"rules"`
	Macros  []*MacroDefinition `yaml:"macros"`
}

// Policy represents a policy file which is composed of a list of rules and macros
type Policy struct {
	Name        string
	Source      string
	Version     string
	Rules       []*RuleDefinition
	Macros      []*MacroDefinition
	TaggedRules map[eval.NormalizedRuleTag][]*RuleDefinition
}

// AddMacro add a macro to the policy
func (p *Policy) AddMacro(def *MacroDefinition) {
	p.Macros = append(p.Macros, def)
}

// AddRule adds a rule to the policy
func (p *Policy) AddRule(def *RuleDefinition) {
	def.Policy = p
	p.Rules = append(p.Rules, def)
}

// AddTaggedRule adds a threat score rule to the policy
func (p *Policy) AddTaggedRule(def *RuleDefinition) {
	def.Policy = p

	normalizedTags := normalizeTags(def.Tags)
	for key, val := range normalizedTags {
		policyRuleListKey := key + ":" + val
		p.TaggedRules[policyRuleListKey] = append(p.TaggedRules[policyRuleListKey], def)
	}
}

func normalizeTags(tags map[string]string) map[string]string {
	normalizedTags := make(map[string]string)
	for key, val := range tags {
		normalizedTags[strings.TrimSpace(strings.ToLower(key))] = strings.TrimSpace(strings.ToLower(val))
	}

	return normalizedTags
}

func parsePolicyDef(name string, source string, def *PolicyDef, macroFilters []MacroFilter, ruleFilters []RuleFilter) (*Policy, error) {
	var errs *multierror.Error

	policy := &Policy{
		Name:    name,
		Source:  source,
		Version: def.Version,
	}
	policy.TaggedRules = make(map[eval.NormalizedRuleTag][]*RuleDefinition)

MACROS:
	for _, macroDef := range def.Macros {
		for _, filter := range macroFilters {
			isMacroAccepted, err := filter.IsMacroAccepted(macroDef)
			if err != nil {
				errs = multierror.Append(errs, &ErrMacroLoad{Definition: macroDef, Err: fmt.Errorf("error when evaluating one of the macro filters: %w", err)})
			}
			if !isMacroAccepted {
				continue MACROS
			}
		}

		if macroDef.ID == "" {
			errs = multierror.Append(errs, &ErrMacroLoad{Err: fmt.Errorf("no ID defined for macro with expression `%s`", macroDef.Expression)})
			continue
		}
		if !validators.CheckRuleID(macroDef.ID) {
			errs = multierror.Append(errs, &ErrMacroLoad{Definition: macroDef, Err: fmt.Errorf("ID does not match pattern `%s`", validators.RuleIDPattern)})
			continue
		}

		policy.AddMacro(macroDef)
	}

	var skipped []struct {
		ruleDefinition *RuleDefinition
		err            error
	}

RULES:
	for _, ruleDef := range def.Rules {
		// set the policy so that when we parse the errors we can get the policy associated
		ruleDef.Policy = policy
		isTagged := false

		for _, filter := range ruleFilters {
			isRuleAccepted, err := filter.IsRuleAccepted(ruleDef)
			if err != nil {
				errs = multierror.Append(errs, &ErrRuleLoad{Definition: ruleDef, Err: err})
			}
			var isTagFilter bool
			if _, isTagFilter = filter.(*RuleTagFilter); isTagFilter && isRuleAccepted {
				isTagged = true
				break
			}
			if !isRuleAccepted {
				// we do not fail directly because one of the rules with the same id can load properly
				if _, ok := filter.(*AgentVersionFilter); ok {
					skipped = append(skipped, struct {
						ruleDefinition *RuleDefinition
						err            error
					}{ruleDefinition: ruleDef, err: ErrRuleAgentVersion})
				} else if _, ok := filter.(*SECLRuleFilter); ok {
					skipped = append(skipped, struct {
						ruleDefinition *RuleDefinition
						err            error
					}{ruleDefinition: ruleDef, err: ErrRuleAgentFilter})
				}

				continue RULES
			}
		}

		if ruleDef.ID == "" {
			errs = multierror.Append(errs, &ErrRuleLoad{Definition: ruleDef, Err: ErrRuleWithoutID})
			continue
		}
		if !validators.CheckRuleID(ruleDef.ID) {
			errs = multierror.Append(errs, &ErrRuleLoad{Definition: ruleDef, Err: ErrRuleIDPattern})
			continue
		}

		if ruleDef.Expression == "" && !ruleDef.Disabled {
			errs = multierror.Append(errs, &ErrRuleLoad{Definition: ruleDef, Err: ErrRuleWithoutExpression})
			continue
		}

		if isTagged {
			policy.AddTaggedRule(ruleDef)
		}

		policy.AddRule(ruleDef)
	}

LOOP:
	for _, s := range skipped {
		// For every skipped rule, if it doesn't match an ID of a policy rule, add an error.
		for _, r := range policy.Rules {
			if s.ruleDefinition.ID == r.ID {
				continue LOOP
			}
		}

		errs = multierror.Append(errs, &ErrRuleLoad{Definition: s.ruleDefinition, Err: s.err})
	}

	return policy, errs.ErrorOrNil()
}

// LoadPolicy load a policy
func LoadPolicy(name string, source string, reader io.Reader, macroFilters []MacroFilter, ruleFilters []RuleFilter) (*Policy, error) {
	var def PolicyDef

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&def); err != nil {
		return nil, &ErrPolicyLoad{Name: name, Err: err}
	}

	return parsePolicyDef(name, source, &def, macroFilters, ruleFilters)
}
