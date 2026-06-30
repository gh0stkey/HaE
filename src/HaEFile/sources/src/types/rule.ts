export interface RulesYAML {
  rules: RuleGroup[];
}

export interface RuleGroup {
  group: string;
  rule: RuleYAMLItem[];
}

export interface RuleYAMLItem {
  name: string;
  loaded: boolean;
  regex: string;
  color: import('./shared').RuleColor;
  sensitive: boolean;
  validator?: import('./shared').ValidatorConfig;
}
