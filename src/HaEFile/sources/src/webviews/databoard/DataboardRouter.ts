import * as vscode from 'vscode';
import { RuleHandler, SettingsHandler, FileHandler } from '../../handlers';
import { Logger, Notifier } from '../../utils/logger';
import {
  Severity,
  QueryRuleResultsParams,
  SettingsState,
  WebviewCommand,
  ExtensionMessage,
  CONFIG_LIMITS,
} from '../../types';
import {
  isValidScanRule,
  isStringInRange,
  isNumberInRange,
  isValidFilePath,
  isValidExtensionList,
} from '../../utils/validation';

interface MessageSender {
  postMessage(message: ExtensionMessage): void;
}

const RULE_COMMANDS: ReadonlySet<string> = new Set([
  'addRule',
  'updateRule',
  'deleteRule',
  'confirmDeleteRule',
  'deleteGroup',
  'renameGroup',
  'importRules',
  'exportRules',
]);

const SETTINGS_COMMANDS: ReadonlySet<string> = new Set([
  'toggleDecoration',
  'setIgnoredExtensions',
  'setDecorationDelay',
  'setMaxFileSize',
  'setMaxResults',
  'setScanTimeout',
  'setScanWorkerMaxConcurrency',
  'setRipgrepPath',
  'validateRipgrepPath',
]);

export class DataboardRouter {
  private readonly _ruleHandler: RuleHandler;
  private readonly _fileHandler: FileHandler;

  constructor(
    private readonly _sender: MessageSender,
    private readonly _callbacks: {
      onClearResults: () => void;
      onRescan: () => Promise<void>;
      onCancelScan: () => Promise<void>;
      onRevalidate: (ruleIds: string[], matchValues?: string[]) => void;
      onUpdateSeverity: (file: string, line: number, column: number, severity: Severity) => void;
      onQueryRuleResults: (params: QueryRuleResultsParams) => void;
      onQueryMatchFiles: (groupName: string, ruleName: string, matchValues: string[]) => void;
      onUpdateMatchSeverity: (
        groupName: string,
        ruleName: string,
        matchValue: string,
        severity: Severity
      ) => void;
      sendSnapshot: () => void;
      sendSettingsUpdate: (settings: Partial<SettingsState>) => void;
      sendRules: () => void;
    },
    private readonly _settingsHandler: SettingsHandler
  ) {
    this._ruleHandler = new RuleHandler();
    this._fileHandler = new FileHandler();
  }

  async handleMessage(message: WebviewCommand): Promise<void> {
    const cmd = message.command;
    if (this._handleSimpleCommand(message)) return;
    if (cmd === 'openFile' || cmd === 'updateSeverity') {
      await this._handleFileCommand(message);
    } else if (
      cmd === 'revalidate' ||
      cmd === 'queryRuleResults' ||
      cmd === 'queryMatchFiles' ||
      cmd === 'updateMatchSeverity'
    ) {
      this._handleQueryCommand(message);
    } else if (RULE_COMMANDS.has(cmd)) {
      await this._handleRuleCommand(message);
    } else if (SETTINGS_COMMANDS.has(cmd)) {
      await this._handleSettingsCommand(message);
    }
  }

  private _handleSimpleCommand(message: WebviewCommand): boolean {
    switch (message.command) {
      case 'webviewReady':
        this._callbacks.sendSnapshot();
        return true;
      case 'clearResults':
        this._callbacks.onClearResults();
        return true;
      case 'rescan':
        void this._callbacks.onRescan();
        return true;
      case 'scanWorkspace':
        void vscode.commands.executeCommand('hae.scanWorkspace');
        return true;
      case 'cancelScan':
        void this._callbacks.onCancelScan();
        return true;
      case 'showInfo':
        if (typeof message.message === 'string') {
          Notifier.info(message.message);
        }
        return true;
      default:
        return false;
    }
  }

  private async _handleFileCommand(message: WebviewCommand): Promise<void> {
    switch (message.command) {
      case 'openFile':
        if (
          !isValidFilePath(message.file) ||
          typeof message.line !== 'number' ||
          message.line < 1
        ) {
          Logger.warn('Invalid openFile command parameters');
          return;
        }
        await this._fileHandler.openFile(
          message.file,
          message.line,
          message.column ?? 0,
          message.match ?? ''
        );
        return;
      case 'updateSeverity':
        if (!isValidFilePath(message.file)) {
          Logger.warn('Invalid updateSeverity command parameters');
          return;
        }
        this._callbacks.onUpdateSeverity(
          message.file,
          message.line,
          message.column,
          message.severity
        );
        return;
    }
  }

  private _handleQueryCommand(message: WebviewCommand): void {
    switch (message.command) {
      case 'revalidate':
        this._callbacks.onRevalidate(message.ruleIds, message.matchValues);
        return;
      case 'queryRuleResults':
        this._callbacks.onQueryRuleResults({
          groupName: message.groupName,
          ruleName: message.ruleName,
          searchTerm: message.searchTerm,
          useRegex: message.useRegex,
          severities: message.severities,
        });
        return;
      case 'queryMatchFiles':
        if (!Array.isArray(message.matchValues) || message.matchValues.length === 0) {
          Logger.warn('Invalid queryMatchFiles: empty matchValues');
          return;
        }
        this._callbacks.onQueryMatchFiles(message.groupName, message.ruleName, message.matchValues);
        return;
      case 'updateMatchSeverity':
        if (typeof message.matchValue !== 'string' || !message.matchValue) {
          Logger.warn('Invalid updateMatchSeverity: missing matchValue');
          return;
        }
        this._callbacks.onUpdateMatchSeverity(
          message.groupName,
          message.ruleName,
          message.matchValue,
          message.severity
        );
        return;
    }
  }

  private async _handleRuleCommand(message: WebviewCommand): Promise<void> {
    try {
      switch (message.command) {
        case 'addRule':
          await this._addRule(message);
          return;
        case 'updateRule':
          await this._updateRule(message);
          return;
        case 'deleteRule':
          await this._deleteRule(message);
          return;
        case 'confirmDeleteRule':
          await this._confirmDeleteRule(message);
          return;
        case 'deleteGroup':
          await this._deleteGroup(message);
          return;
        case 'renameGroup':
          await this._renameGroup(message);
          return;
        case 'importRules':
          await this._importRules();
          return;
        case 'exportRules':
          await this._ruleHandler.exportRulesYAML();
          return;
      }
    } catch (err: unknown) {
      Logger.error(`Error handling rule command ${message.command}`, this._toError(err));
    }
  }

  private async _addRule(message: Extract<WebviewCommand, { command: 'addRule' }>): Promise<void> {
    if (!isValidScanRule(message.rule)) {
      Logger.error('Invalid rule data for addRule command');
      return;
    }
    if (await this._ruleHandler.addRule(message.rule)) {
      this._callbacks.sendRules();
    }
  }

  private async _updateRule(
    message: Extract<WebviewCommand, { command: 'updateRule' }>
  ): Promise<void> {
    if (!isValidScanRule(message.rule)) {
      Logger.error('Invalid rule data for updateRule command');
      return;
    }
    if (await this._ruleHandler.updateRule(message.rule)) {
      this._callbacks.sendRules();
    }
  }

  private async _deleteRule(
    message: Extract<WebviewCommand, { command: 'deleteRule' }>
  ): Promise<void> {
    if (typeof message.id !== 'string' || message.id.length === 0) {
      Logger.error('Invalid id for deleteRule command');
      return;
    }
    if (await this._ruleHandler.deleteRule(message.id)) {
      this._callbacks.sendRules();
    }
  }

  private async _confirmDeleteRule(
    message: Extract<WebviewCommand, { command: 'confirmDeleteRule' }>
  ): Promise<void> {
    if (typeof message.id !== 'string' || message.id.length === 0) {
      Logger.error('Invalid id for confirmDeleteRule command');
      return;
    }
    if (await this._ruleHandler.confirmDeleteRule(message.id)) {
      this._callbacks.sendRules();
    }
  }

  private async _deleteGroup(
    message: Extract<WebviewCommand, { command: 'deleteGroup' }>
  ): Promise<void> {
    if (!isStringInRange(message.groupName, 1, CONFIG_LIMITS.GROUP_NAME_MAX_LENGTH)) {
      Logger.error('Invalid group name for deleteGroup command');
      return;
    }
    if (await this._ruleHandler.deleteGroup(message.groupName)) {
      this._callbacks.sendRules();
    }
  }

  private async _renameGroup(
    message: Extract<WebviewCommand, { command: 'renameGroup' }>
  ): Promise<void> {
    if (
      !isStringInRange(message.oldName, 1, CONFIG_LIMITS.GROUP_NAME_MAX_LENGTH) ||
      !isStringInRange(message.newName, 1, CONFIG_LIMITS.GROUP_NAME_MAX_LENGTH)
    ) {
      Logger.error('Invalid group names for renameGroup command');
      return;
    }
    if (await this._ruleHandler.renameGroup(message.oldName, message.newName)) {
      this._callbacks.sendRules();
    }
  }

  private async _importRules(): Promise<void> {
    const result = await this._ruleHandler.importRulesYAML();
    if (result.success) {
      this._callbacks.sendRules();
    }
  }

  private async _handleSettingsCommand(message: WebviewCommand): Promise<void> {
    try {
      switch (message.command) {
        case 'toggleDecoration':
          await this._toggleDecoration(message);
          return;
        case 'setIgnoredExtensions':
          await this._setIgnoredExtensions(message);
          return;
        case 'setDecorationDelay':
          await this._setDecorationDelay(message);
          return;
        case 'setMaxFileSize':
          await this._setMaxFileSize(message);
          return;
        case 'setMaxResults':
          await this._setMaxResults(message);
          return;
        case 'setScanTimeout':
          await this._setScanTimeout(message);
          return;
        case 'setScanWorkerMaxConcurrency':
          await this._setScanWorkerMaxConcurrency(message);
          return;
        case 'setRipgrepPath':
          await this._setRipgrepPath(message);
          return;
        case 'validateRipgrepPath':
          await this._validateRipgrepPath(message);
          return;
      }
    } catch (err: unknown) {
      Logger.error(`Error handling settings command ${message.command}`, this._toError(err));
    }
  }

  private async _toggleDecoration(
    message: Extract<WebviewCommand, { command: 'toggleDecoration' }>
  ): Promise<void> {
    if (typeof message.enabled !== 'boolean') {
      Logger.error('Invalid enabled value for toggleDecoration command');
      return;
    }
    await this._settingsHandler.toggleDecoration(message.enabled);
    this._callbacks.sendSettingsUpdate({ decorationEnabled: message.enabled });
  }

  private async _setIgnoredExtensions(
    message: Extract<WebviewCommand, { command: 'setIgnoredExtensions' }>
  ): Promise<void> {
    if (!isValidExtensionList(message.extensions)) {
      Logger.error('Invalid extensions list for setIgnoredExtensions command');
      return;
    }
    await this._settingsHandler.setIgnoredExtensions(message.extensions);
    this._callbacks.sendSettingsUpdate({ ignoredExtensions: message.extensions });
  }

  private async _setDecorationDelay(
    message: Extract<WebviewCommand, { command: 'setDecorationDelay' }>
  ): Promise<void> {
    if (
      !isNumberInRange(
        message.delay,
        CONFIG_LIMITS.DECORATION_DELAY_MIN,
        CONFIG_LIMITS.DECORATION_DELAY_MAX
      )
    ) {
      Logger.error(
        `Invalid delay value (must be ${CONFIG_LIMITS.DECORATION_DELAY_MIN}-${CONFIG_LIMITS.DECORATION_DELAY_MAX}ms)`
      );
      return;
    }
    await this._settingsHandler.setDecorationDelay(message.delay);
    this._callbacks.sendSettingsUpdate({ decorationDelay: message.delay });
  }

  private async _setMaxFileSize(
    message: Extract<WebviewCommand, { command: 'setMaxFileSize' }>
  ): Promise<void> {
    if (
      !isNumberInRange(
        message.size,
        CONFIG_LIMITS.MAX_FILE_SIZE_MIN,
        CONFIG_LIMITS.MAX_FILE_SIZE_MAX
      )
    ) {
      Logger.error(
        `Invalid size value (must be ${(CONFIG_LIMITS.MAX_FILE_SIZE_MIN / 1024 / 1024).toFixed(2)}-${CONFIG_LIMITS.MAX_FILE_SIZE_MAX / 1024 / 1024}MB)`
      );
      return;
    }
    await this._settingsHandler.setMaxFileSize(message.size);
    this._callbacks.sendSettingsUpdate({ maxFileSize: message.size });
  }

  private async _setMaxResults(
    message: Extract<WebviewCommand, { command: 'setMaxResults' }>
  ): Promise<void> {
    if (
      !isNumberInRange(message.value, CONFIG_LIMITS.MAX_RESULTS_MIN, CONFIG_LIMITS.MAX_RESULTS_MAX)
    ) {
      Logger.error(
        `Invalid value (must be ${CONFIG_LIMITS.MAX_RESULTS_MIN}-${CONFIG_LIMITS.MAX_RESULTS_MAX})`
      );
      return;
    }
    await this._settingsHandler.setMaxResults(message.value);
    this._callbacks.sendSettingsUpdate({ maxResults: message.value });
  }

  private async _setScanTimeout(
    message: Extract<WebviewCommand, { command: 'setScanTimeout' }>
  ): Promise<void> {
    if (
      !isNumberInRange(
        message.value,
        CONFIG_LIMITS.SCAN_TIMEOUT_MIN,
        CONFIG_LIMITS.SCAN_TIMEOUT_MAX
      )
    ) {
      Logger.error(
        `Invalid value (must be ${CONFIG_LIMITS.SCAN_TIMEOUT_MIN / 1000}-${CONFIG_LIMITS.SCAN_TIMEOUT_MAX / 1000}s)`
      );
      return;
    }
    await this._settingsHandler.setScanTimeout(message.value);
    this._callbacks.sendSettingsUpdate({ scanTimeout: message.value });
  }

  private async _setScanWorkerMaxConcurrency(
    message: Extract<WebviewCommand, { command: 'setScanWorkerMaxConcurrency' }>
  ): Promise<void> {
    if (
      typeof message.value !== 'number' ||
      !Number.isFinite(message.value) ||
      message.value < CONFIG_LIMITS.SCAN_WORKER_MAX_CONCURRENCY_MIN
    ) {
      Logger.error(`Invalid value (must be >= ${CONFIG_LIMITS.SCAN_WORKER_MAX_CONCURRENCY_MIN})`);
      return;
    }
    await this._settingsHandler.setScanWorkerMaxConcurrency(message.value);
    this._callbacks.sendSettingsUpdate({ scanWorkerMaxConcurrency: message.value });
  }

  private async _setRipgrepPath(
    message: Extract<WebviewCommand, { command: 'setRipgrepPath' }>
  ): Promise<void> {
    if (await this._settingsHandler.setRipgrepPath(message.path)) {
      this._callbacks.sendSettingsUpdate({ ripgrepPath: this._settingsHandler.getRipgrepPath() });
    }
  }

  private async _validateRipgrepPath(
    message: Extract<WebviewCommand, { command: 'validateRipgrepPath' }>
  ): Promise<void> {
    const isValid = await this._settingsHandler.validateRipgrepPath(message.path);
    this._sender.postMessage({
      type: 'ripgrepValidation',
      valid: isValid,
      path: message.path,
    });
  }

  private _toError(err: unknown): Error {
    if (err instanceof Error) return err;
    try {
      return new Error(JSON.stringify(err));
    } catch {
      return new Error(String(err));
    }
  }
}
