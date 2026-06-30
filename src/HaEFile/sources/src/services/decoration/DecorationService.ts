import * as vscode from 'vscode';
import {
  ScanRule,
  RuleColor,
  ActiveFilePayload,
  ActiveFileResultGroup,
  ScanResult,
} from '../../types';
import { RuleService } from '../rules/RuleService';
import { ConfigService } from '../config/ConfigService';
import { groupRulesByPattern } from '../../utils/array';
import { createScopedLogger } from '../../utils/logger';

const logger = createScopedLogger('DecorationService');
const COLOR_MAP: Record<RuleColor, { light: string; dark: string; border: string }> = {
  red: {
    light: 'rgba(255, 107, 107, 0.3)',
    dark: 'rgba(255, 107, 107, 0.2)',
    border: '#FF6B6B',
  },
  orange: {
    light: 'rgba(255, 165, 0, 0.3)',
    dark: 'rgba(255, 165, 0, 0.2)',
    border: '#FFA500',
  },
  yellow: {
    light: 'rgba(255, 217, 61, 0.3)',
    dark: 'rgba(255, 217, 61, 0.2)',
    border: '#FFD93D',
  },
  green: {
    light: 'rgba(144, 238, 144, 0.3)',
    dark: 'rgba(144, 238, 144, 0.2)',
    border: '#90EE90',
  },
  cyan: {
    light: 'rgba(0, 255, 255, 0.3)',
    dark: 'rgba(0, 255, 255, 0.2)',
    border: '#00FFFF',
  },
  blue: {
    light: 'rgba(0, 123, 255, 0.3)',
    dark: 'rgba(0, 123, 255, 0.2)',
    border: '#007BFF',
  },
  pink: {
    light: 'rgba(255, 192, 203, 0.3)',
    dark: 'rgba(255, 192, 203, 0.2)',
    border: '#FFC0CB',
  },
  magenta: {
    light: 'rgba(255, 0, 255, 0.3)',
    dark: 'rgba(255, 0, 255, 0.2)',
    border: '#FF00FF',
  },
  gray: {
    light: 'rgba(128, 128, 128, 0.3)',
    dark: 'rgba(128, 128, 128, 0.2)',
    border: '#808080',
  },
  none: {
    light: 'transparent',
    dark: 'transparent',
    border: 'transparent',
  },
};

export class DecorationService {
  private static instance: DecorationService | null = null;

  private disposed = false;

  private decorationTypes: Map<RuleColor, vscode.TextEditorDecorationType>;

  private updateTimeouts: Map<string, NodeJS.Timeout> = new Map();

  private disposables: vscode.Disposable[] = [];

  private enabled: boolean = true;

  private invalidRegexWarnings: Set<string> = new Set();

  private configService: ConfigService;

  private ruleService: RuleService;

  private _onFileResults?: (payload: ActiveFilePayload) => void;

  private _lastFilePayload?: ActiveFilePayload;

  private constructor() {
    this.configService = ConfigService.getInstance();
    this.ruleService = RuleService.getInstance();
    this.decorationTypes = this.createDecorationTypes();
    this.loadConfiguration();
  }

  static getInstance(): DecorationService {
    if (DecorationService.instance === null || DecorationService.instance.disposed) {
      DecorationService.instance = new DecorationService();
    }

    return DecorationService.instance;
  }

  initialize(context: vscode.ExtensionContext): void {
    this.disposables.push(
      this.configService.onConfigChange(() => {
        this.loadConfiguration();
        this.refreshAllEditors();
      })
    );
    this.disposables.push(
      vscode.workspace.onDidOpenTextDocument((document) => {
        this.updateDecorations(document);
      })
    );
    this.disposables.push(
      vscode.workspace.onDidCloseTextDocument((document) => {
        const key = document.uri.toString();
        const timeout = this.updateTimeouts.get(key);
        if (timeout) {
          clearTimeout(timeout);
          this.updateTimeouts.delete(key);
        }
      })
    );
    this.disposables.push(
      vscode.workspace.onDidChangeTextDocument((event) => {
        this.scheduleUpdate(event.document);
      })
    );
    this.disposables.push(
      vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor) {
          this.updateDecorations(editor.document);
        }
      })
    );
    vscode.window.visibleTextEditors.forEach((editor) => {
      this.updateDecorations(editor.document);
    });
    context.subscriptions.push(...this.disposables);
  }

  private loadConfiguration(): void {
    this.enabled = this.configService.isDecorationEnabled();
    this.invalidRegexWarnings.clear();
  }

  private createDecorationTypes(): Map<RuleColor, vscode.TextEditorDecorationType> {
    const types = new Map<RuleColor, vscode.TextEditorDecorationType>();
    Object.entries(COLOR_MAP).forEach(([color, colors]) => {
      const decorationType = vscode.window.createTextEditorDecorationType({
        backgroundColor: colors.light,
        light: { backgroundColor: colors.light },
        dark: { backgroundColor: colors.dark },
        border: `1px solid ${colors.border}`,
        borderRadius: '3px',
        overviewRulerColor: colors.border,
        overviewRulerLane: vscode.OverviewRulerLane.Right,
      });
      types.set(color as RuleColor, decorationType);
    });

    return types;
  }

  private scheduleUpdate(document: vscode.TextDocument): void {
    if (!this.enabled) {
      return;
    }
    const delay = this.configService.getDecorationDelay();
    const key = document.uri.toString();
    const existingTimeout = this.updateTimeouts.get(key);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }
    const timeout = setTimeout(() => {
      this.updateTimeouts.delete(key);
      this.updateDecorations(document);
    }, delay);
    this.updateTimeouts.set(key, timeout);
  }

  private isEditorShowingDocument(
    editor: vscode.TextEditor,
    document: vscode.TextDocument
  ): boolean {
    if (!vscode.window.visibleTextEditors.includes(editor)) {
      return false;
    }
    return editor.document.uri.toString() === document.uri.toString();
  }

  private emitNoMatches(filePath: string): void {
    if (!this._onFileResults) {
      return;
    }
    this.emitFileResults(filePath, []);
  }

  private updateDecorations(document: vscode.TextDocument): void {
    if (!this.enabled) {
      return;
    }
    const editor = vscode.window.visibleTextEditors.find((e) => e.document === document);
    if (!editor) {
      return;
    }

    if (this.configService.isExtensionIgnored(document.uri.fsPath)) {
      this.clearDecorations(editor);
      this.emitNoMatches(document.uri.fsPath);
      return;
    }

    const maxFileSize = this.configService.getMaxFileSize();
    if (maxFileSize > 0) {
      const fileSize = Buffer.byteLength(document.getText(), 'utf8');
      if (fileSize > maxFileSize) {
        this.clearDecorations(editor);
        this.emitNoMatches(document.uri.fsPath);

        return;
      }
    }
    const rules = this.ruleService.getEnabledRules();
    if (rules.length === 0) {
      this.clearDecorations(editor);
      this.emitNoMatches(document.uri.fsPath);

      return;
    }

    void this.processRulesAsync(editor, document, rules);
  }

  private async processRulesAsync(
    editor: vscode.TextEditor,
    document: vscode.TextDocument,
    rules: ScanRule[]
  ): Promise<void> {
    const decorationsByColor = new Map<RuleColor, vscode.DecorationOptions[]>();
    const fileResultGroups: ActiveFileResultGroup[] = [];
    const rulesByPattern = this.getValidRulesByPattern(rules);

    for (const [key, patternRules] of rulesByPattern) {
      if (!this.isEditorShowingDocument(editor, document)) {
        return;
      }

      const [pattern, sensitiveStr] = key.split('::');
      const isSensitive = sensitiveStr === 'true';
      const firstRule = patternRules[0];

      const matches = await this.findMatches(document, pattern, isSensitive, firstRule);

      if (!this.isEditorShowingDocument(editor, document)) {
        return;
      }

      for (const rule of patternRules) {
        if (matches.length > 0) {
          if (!decorationsByColor.has(rule.color)) {
            decorationsByColor.set(rule.color, []);
          }
          this.collectRuleMatches(document, rule, matches, decorationsByColor, fileResultGroups);
        }
      }
    }

    if (!this.isEditorShowingDocument(editor, document)) {
      return;
    }

    this.decorationTypes.forEach((decorationType, color) => {
      const decorations = decorationsByColor.get(color) || [];
      editor.setDecorations(decorationType, decorations);
    });

    if (this._onFileResults) {
      this.emitFileResults(document.uri.fsPath, fileResultGroups);
    }
  }

  private getValidRulesByPattern(rules: ScanRule[]): Map<string, ScanRule[]> {
    const validRules = rules.filter((rule) => {
      if (!rule.regex || typeof rule.regex !== 'string' || rule.regex.trim() === '') {
        if (!this.invalidRegexWarnings.has(rule.id)) {
          this.invalidRegexWarnings.add(rule.id);
          logger.warn(
            `Skipping rule "${rule.name}" (ID: ${rule.id}) - missing or invalid regex field`
          );
        }
        return false;
      }
      return true;
    });
    return groupRulesByPattern(validRules);
  }

  private collectRuleMatches(
    document: vscode.TextDocument,
    rule: ScanRule,
    matches: { range: vscode.Range; matchText: string }[],
    decorationsByColor: Map<RuleColor, vscode.DecorationOptions[]>,
    fileResultGroups: ActiveFileResultGroup[]
  ): void {
    const ruleResults: ScanResult[] = [];
    for (const match of matches) {
      const hoverMessage = new vscode.MarkdownString();
      hoverMessage.isTrusted = false;
      hoverMessage.supportHtml = false;
      hoverMessage.appendText(`[${rule.color}] ${rule.group} -> ${rule.name}`);
      decorationsByColor.get(rule.color)!.push({ range: match.range, hoverMessage });
      ruleResults.push({
        file: document.uri.fsPath,
        line: match.range.start.line + 1,
        column: match.range.start.character,
        match: match.matchText,
        ruleId: rule.id,
        ruleName: rule.name,
        color: rule.color,
      });
    }
    fileResultGroups.push({
      groupName: rule.group,
      ruleName: rule.name,
      ruleId: rule.id,
      color: rule.color,
      results: ruleResults,
    });
  }

  private emitFileResults(filePath: string, groups: ActiveFileResultGroup[]): void {
    if (!this._onFileResults) {
      return;
    }
    let totalCount = 0;
    for (const g of groups) {
      totalCount += g.results.length;
    }
    const payload: ActiveFilePayload = { filePath, groups, totalCount };
    this._lastFilePayload = payload;
    this._onFileResults(payload);
  }

  private async findMatches(
    document: vscode.TextDocument,
    pattern: string,
    sensitive: boolean,
    rule: ScanRule
  ): Promise<{ range: vscode.Range; matchText: string }[]> {
    const results: { range: vscode.Range; matchText: string }[] = [];
    const text = document.getText();
    const configuredMaxResults = this.configService.getMaxResults();
    const maxMatches = configuredMaxResults > 0 ? configuredMaxResults : Number.MAX_SAFE_INTEGER;
    const maxIterations =
      configuredMaxResults > 0 ? Math.max(configuredMaxResults * 2, 100000) : 500000;

    try {
      const flags = sensitive ? 'g' : 'gi';
      const regex = new RegExp(pattern, flags);
      regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      let iterations = 0;

      while ((match = regex.exec(text)) !== null) {
        iterations++;

        if (results.length >= maxMatches) {
          logger.warn(
            `Pattern exceeded configured maxResults (${configuredMaxResults}), stopping decoration`
          );
          break;
        }
        if (iterations >= maxIterations) {
          logger.warn(`Pattern exceeded ${maxIterations} iterations, stopping decoration`);
          break;
        }

        const matchText = match[1] !== undefined ? match[1] : match[0];
        const matchIndex =
          match[1] !== undefined ? match.index + match[0].indexOf(match[1]) : match.index;
        const startPos = document.positionAt(matchIndex);
        const endPos = document.positionAt(matchIndex + matchText.length);
        const range = new vscode.Range(startPos, endPos);

        results.push({ range, matchText });

        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    } catch (error) {
      if (!this.invalidRegexWarnings.has(rule.id)) {
        this.invalidRegexWarnings.add(rule.id);
        logger.error(`Unexpected error in rule "${rule.name}" (ID: ${rule.id})`, error);
      }
    }

    return results;
  }

  private clearDecorations(editor: vscode.TextEditor): void {
    this.decorationTypes.forEach((decorationType) => {
      editor.setDecorations(decorationType, []);
    });
  }

  private refreshAllEditors(): void {
    vscode.window.visibleTextEditors.forEach((editor) => {
      if (this.enabled) {
        this.updateDecorations(editor.document);
      } else {
        this.clearDecorations(editor);
      }
    });
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    void this.configService.setDecorationEnabled(enabled);
    this.refreshAllEditors();
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  onFileResults(callback: (payload: ActiveFilePayload) => void): void {
    this._onFileResults = callback;
    const editor = vscode.window.activeTextEditor;
    if (editor) {
      this.updateDecorations(editor.document);
    }
  }

  getLastFileResults(): ActiveFilePayload | undefined {
    return this._lastFilePayload;
  }

  refreshVisibleEditors(): void {
    this.refreshAllEditors();
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.updateTimeouts.forEach((timeout) => clearTimeout(timeout));
    this.updateTimeouts.clear();
    this.decorationTypes.forEach((type) => type.dispose());
    this.decorationTypes.clear();
    this.disposables.forEach((d) => d.dispose());
    this.disposables = [];
    this.invalidRegexWarnings.clear();
  }
}
