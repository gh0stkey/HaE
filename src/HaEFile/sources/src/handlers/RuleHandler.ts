import * as vscode from 'vscode';
import { ScanRule } from '../types';
import { RuleService } from '../services';
import { createScopedNotifier } from '../utils/logger';

const notify = createScopedNotifier('Rule');

export class RuleHandler {
  private ruleService: RuleService;

  constructor() {
    this.ruleService = RuleService.getInstance();
  }

  async addRule(rule: ScanRule): Promise<boolean> {
    if (!rule.id || rule.id.startsWith('new_')) {
      rule = { ...rule, id: this.ruleService.generateRuleId(rule.group, rule.name) };
    }
    const error = this.ruleService.validateRule(rule);
    if (error) {
      notify.error('Create rule failed', error);

      return false;
    }
    this.ruleService.addRule(rule);
    await this.ruleService.saveRules();
    notify.success('Create rule', rule.name);

    return true;
  }

  async updateRule(rule: ScanRule): Promise<boolean> {
    const error = this.ruleService.validateRule(rule);
    if (error) {
      notify.error('Update rule failed', error);

      return false;
    }
    const success = this.ruleService.updateRule(rule.id, rule);
    if (success) {
      await this.ruleService.saveRules();
      notify.success('Update rule', rule.name);
    }

    return success;
  }

  async deleteRule(id: string): Promise<boolean> {
    const rule = this.ruleService.getRule(id);
    const ruleName = rule?.name || id;
    const success = this.ruleService.deleteRule(id);
    if (success) {
      await this.ruleService.saveRules();
      notify.success('Delete rule', ruleName);
    }

    return success;
  }

  async confirmDeleteRule(id: string): Promise<boolean> {
    const rule = this.ruleService.getRule(id);
    const result = await notify.confirm(`Confirm delete rule "${rule?.name || id}"`, 'Delete');
    if (result === 'Delete') {
      return this.deleteRule(id);
    }

    return false;
  }

  async deleteGroup(groupName: string): Promise<boolean> {
    const result = await notify.confirm(
      `Confirm delete group "${groupName}" and all its rules`,
      'Delete'
    );
    if (result !== 'Delete') {
      return false;
    }
    this.ruleService.deleteGroup(groupName);
    await this.ruleService.saveRules();
    notify.success('Delete group', groupName);

    return true;
  }

  async renameGroup(oldName: string, newName: string): Promise<boolean> {
    if (!oldName || !newName || oldName === newName) {
      return false;
    }
    const success = this.ruleService.renameGroup(oldName, newName);
    if (success) {
      await this.ruleService.saveRules();
      notify.success('Rename group', `${oldName} → ${newName}`);
    }

    return success;
  }

  async importRulesYAML(): Promise<{ success: boolean; count?: number }> {
    const uri = await vscode.window.showOpenDialog({
      filters: { YAML: ['yml', 'yaml'] },
      canSelectMany: false,
    });
    if (uri && uri[0]) {
      try {
        const content = await vscode.workspace.fs.readFile(uri[0]);
        const yamlContent = Buffer.from(content).toString('utf8');
        const result = this.ruleService.importRulesFromYAML(yamlContent);
        if (result.success) {
          await this.ruleService.saveRules();
          notify.success('Import rules from YAML', `${result.count} rules imported`);

          return { success: true, count: result.count };
        } else {
          notify.error('Import rules from YAML failed', result.error);

          return { success: false };
        }
      } catch (error) {
        notify.error('Import rules from YAML', error, 'Failed to read file');

        return { success: false };
      }
    }

    return { success: false };
  }

  async exportRulesYAML(): Promise<boolean> {
    const yamlContent = this.ruleService.exportRulesToYAML();
    const uri = await vscode.window.showSaveDialog({
      filters: { YAML: ['yml', 'yaml'] },
      defaultUri: vscode.Uri.file('Rules.yml'),
    });
    if (uri) {
      await vscode.workspace.fs.writeFile(uri, Buffer.from(yamlContent));
      const count = this.ruleService.getRules().length;
      notify.success('Export rules to YAML', `${count} rules exported`);

      return true;
    }

    return false;
  }
}
