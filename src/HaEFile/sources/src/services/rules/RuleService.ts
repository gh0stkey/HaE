import * as vscode from 'vscode';
import * as yaml from 'js-yaml';
import { ScanRule, RulesYAML, RuleYAMLItem } from '../../types';
import { ConfigService } from '../config/ConfigService';
import { validateRules } from '../../utils/validation';

export class RuleService {
  private static instance: RuleService | null = null;

  private disposed = false;

  private rules: ScanRule[] = [];

  private configService: ConfigService;

  private configChangeDisposable: vscode.Disposable | undefined;

  private constructor() {
    this.configService = ConfigService.getInstance();
    this.loadRules();
    this.configChangeDisposable = this.configService.onConfigChange(() => {
      this.loadRules();
    });
  }

  static getInstance(): RuleService {
    if (RuleService.instance === null || RuleService.instance.disposed) {
      RuleService.instance = new RuleService();
    }

    return RuleService.instance;
  }

  private loadRules(): void {
    this.rules = validateRules(this.configService.getRawRules());
  }

  async saveRules(): Promise<void> {
    await this.configService.setRules(this.rules);
    this.loadRules();
  }

  getRules(): ScanRule[] {
    return this.rules;
  }

  getEnabledRules(): ScanRule[] {
    return this.rules.filter((rule) => rule.loaded);
  }

  getRule(id: string): ScanRule | undefined {
    return this.rules.find((rule) => rule.id === id);
  }

  addRule(rule: ScanRule): void {
    this.rules.push(rule);
  }

  updateRule(id: string, updates: Partial<ScanRule>): boolean {
    const index = this.rules.findIndex((rule) => rule.id === id);
    if (index !== -1) {
      this.rules[index] = { ...updates, id } as ScanRule;

      return true;
    }

    return false;
  }

  deleteRule(id: string): boolean {
    const index = this.rules.findIndex((rule) => rule.id === id);
    if (index !== -1) {
      this.rules.splice(index, 1);

      return true;
    }

    return false;
  }

  deleteGroup(groupName: string): void {
    this.rules = this.rules.filter((rule) => rule.group !== groupName);
  }

  renameGroup(oldName: string, newName: string): boolean {
    if (!oldName || !newName || oldName === newName) {
      return false;
    }
    let renamed = false;
    this.rules = this.rules.map((rule) => {
      if (rule.group === oldName) {
        renamed = true;

        return { ...rule, group: newName };
      }

      return rule;
    });

    return renamed;
  }

  validateRule(rule: ScanRule): string | null {
    if (!rule.id || rule.id.trim() === '') {
      return 'Rule ID is required';
    }
    if (!rule.name || rule.name.trim() === '') {
      return 'Rule name is required';
    }
    if (!rule.regex || rule.regex.trim() === '') {
      return 'Regex pattern is required';
    }
    if (!rule.group || rule.group.trim() === '') {
      return 'Group is required';
    }
    try {
      const flags = rule.sensitive ? '' : 'i';
      new RegExp(rule.regex, flags);
    } catch (error) {
      return `Invalid regex pattern: ${error}`;
    }

    return null;
  }

  importRulesFromYAML(yamlContent: string): { success: boolean; error?: string; count?: number } {
    try {
      const parsed = yaml.load(yamlContent) as RulesYAML;
      if (!parsed || !parsed.rules || !Array.isArray(parsed.rules)) {
        return { success: false, error: 'Invalid YAML structure. Expected "rules" array.' };
      }
      const newRules: ScanRule[] = [];
      for (const ruleGroup of parsed.rules) {
        if (
          typeof ruleGroup.group !== 'string' ||
          ruleGroup.group.trim() === '' ||
          !Array.isArray(ruleGroup.rule)
        ) {
          continue;
        }
        for (const ruleItem of ruleGroup.rule) {
          const scanRule = this.yamlItemToScanRule(ruleItem, ruleGroup.group);
          newRules.push(scanRule);
        }
      }
      this.rules = newRules;

      return { success: true, count: newRules.length };
    } catch (error) {
      return {
        success: false,
        error: `Failed to parse YAML: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  exportRulesToYAML(): string {
    const groupMap = new Map<string, RuleYAMLItem[]>();
    for (const rule of this.rules) {
      if (!groupMap.has(rule.group)) {
        groupMap.set(rule.group, []);
      }
      groupMap.get(rule.group)!.push(this.scanRuleToYAMLItem(rule));
    }
    const yamlData: RulesYAML = {
      rules: Array.from(groupMap.entries()).map(([groupName, rules]) => ({
        group: groupName,
        rule: rules,
      })),
    };

    return yaml.dump(yamlData, {
      indent: 2,
      lineWidth: -1,
      noRefs: true,
    });
  }

  generateRuleId(group: string, name: string): string {
    const base = `${group}-${name}`
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
    const random = Math.random().toString(36).substring(2, 8);
    const id = `${base}-${Date.now()}-${random}`;
    if (this.rules.some((r) => r.id === id)) {
      return this.generateRuleId(group, name);
    }

    return id;
  }

  private yamlItemToScanRule(item: RuleYAMLItem, groupName: string): ScanRule {
    return {
      id: this.generateRuleId(groupName, item.name),
      name: item.name,
      group: groupName,
      loaded: item.loaded,
      regex: item.regex,
      color: item.color,
      sensitive: item.sensitive,
      validator: item.validator,
    };
  }

  private scanRuleToYAMLItem(rule: ScanRule): RuleYAMLItem {
    const item: RuleYAMLItem = {
      name: rule.name,
      loaded: rule.loaded,
      regex: rule.regex,
      color: rule.color,
      sensitive: rule.sensitive,
    };
    if (rule.validator) {
      item.validator = rule.validator;
    }

    return item;
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.configChangeDisposable?.dispose();
    this.configChangeDisposable = undefined;
    this.rules = [];
  }
}
