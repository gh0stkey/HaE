import * as vscode from 'vscode';
import {
  ScanResult,
  Severity,
  RuleColor,
  GroupSummary,
  RuleSummary,
  ScanSummary,
  MatchSummary,
  FileHit,
  QueryRuleResultsParams,
  ActiveFilePayload,
  ScanSessionState,
  SettingsState,
  StateSnapshot,
  ExtensionMessage,
  CONFIG_LIMITS,
} from '../../types';
import {
  ConfigService,
  RuleService,
  ScanService,
  DecorationService,
  JobController,
} from '../../services';
import { Logger, createScopedNotifier } from '../../utils/logger';
import { DataboardRouter } from './DataboardRouter';
import { SettingsHandler } from '../../handlers';

const notify = createScopedNotifier('Databoard');

export class DataboardProvider implements vscode.WebviewViewProvider {
  public static readonly viewId = 'hae.databoard';

  private _scanResults: Map<string, ScanResult[]> = new Map();

  private _lastScanPaths?: string[];

  private _lastDuration?: number;

  private _validatingRuleIds = new Set<string>();
  private _validatingMatchValues = new Set<string>();

  private _scanSession: ScanSessionState = {
    sessionId: 0,
    phase: 'idle',
    viewState: 'landing',
    hasResults: false,
  };

  private _visibilityTimer?: ReturnType<typeof setTimeout>;

  private _onSeverityChanged?: (results: Map<string, ScanResult[]>) => void;

  private _lastQueryParams?: QueryRuleResultsParams;

  private _queryVersion = 0;
  private _queryVersionKey = '';
  private _lastRuleResultsPushAt = 0;

  private _matchIndexKey = '';
  private _matchIndexDirty = true;
  private _matchIndex = new Map<
    string,
    { results: ScanResult[]; severity: Severity; color: string; ruleId: string }
  >();

  private readonly _configService: ConfigService;

  private readonly _ruleService: RuleService;

  private readonly _settingsHandler: SettingsHandler;

  private _view?: vscode.WebviewView;

  private readonly _messageRouter: DataboardRouter;

  constructor(private readonly _extensionUri: vscode.Uri) {
    this._configService = ConfigService.getInstance();
    this._ruleService = RuleService.getInstance();
    this._settingsHandler = new SettingsHandler();
    this._messageRouter = new DataboardRouter(
      {
        postMessage: (msg) => this._postMessage(msg),
      },
      {
        onClearResults: () => this.clearResults(),
        onRescan: () => this._rescan(),
        onCancelScan: () => this._cancelScan(),
        onRevalidate: (ruleIds, matchValues) => this._revalidate(ruleIds, matchValues),
        onUpdateSeverity: (file, line, column, severity) =>
          this._updateSeverity(file, line, column, severity),
        onQueryRuleResults: (params) => this.queryRuleResults(params),
        onQueryMatchFiles: (groupName, ruleName, matchValues) =>
          this.queryMatchFiles(groupName, ruleName, matchValues),
        onUpdateMatchSeverity: (groupName, ruleName, matchValue, severity) =>
          this._updateMatchSeverity(groupName, ruleName, matchValue, severity),
        sendSnapshot: () => this._sendSnapshot(),
        sendSettingsUpdate: (settings) => this._sendSettingsUpdate(settings),
        sendRules: () =>
          this._postMessage({ type: 'loadRules', rules: this._ruleService.getRules() }),
      },
      this._settingsHandler
    );
    this._configService.onConfigChange(() => {
      this._sendSnapshot();
    });
  }

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ): void {
    this._view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [
        vscode.Uri.joinPath(this._extensionUri, 'webview-ui', 'dist'),
        this._extensionUri,
      ],
    };
    webviewView.webview.html = this._getHtml(webviewView.webview);
    webviewView.webview.onDidReceiveMessage(async (message) => {
      await this._messageRouter.handleMessage(message);
    });
    this._scheduleInitialDataPush();
    webviewView.onDidChangeVisibility(() => {
      this._clearVisibilityTimer();
      if (webviewView.visible) {
        this._scheduleInitialDataPush();
      }
    });
  }

  private _clearVisibilityTimer(): void {
    if (this._visibilityTimer) {
      clearTimeout(this._visibilityTimer);
      this._visibilityTimer = undefined;
    }
  }

  private _scheduleInitialDataPush(): void {
    this._clearVisibilityTimer();
    this._visibilityTimer = setTimeout(() => {
      this._visibilityTimer = undefined;
      this._sendSnapshot();
    }, CONFIG_LIMITS.WEBVIEW_INIT_DELAY);
  }

  private _postMessage(message: ExtensionMessage): void {
    this._view?.webview.postMessage(message);
  }

  private _buildSettings(): SettingsState {
    return {
      decorationEnabled: this._settingsHandler.isDecorationEnabled(),
      decorationDelay: this._settingsHandler.getDecorationDelay(),
      maxFileSize: this._settingsHandler.getMaxFileSize(),
      maxResults: this._settingsHandler.getMaxResults(),
      scanTimeout: this._settingsHandler.getScanTimeout(),
      scanWorkerMaxConcurrency: this._settingsHandler.getScanWorkerMaxConcurrency(),
      ignoredExtensions: this._settingsHandler.getIgnoredExtensions(),
      ripgrepPath: this._settingsHandler.getRipgrepPath(),
    };
  }

  private buildStateSnapshot(): StateSnapshot {
    const decorationService = DecorationService.getInstance();
    const lastPayload = decorationService.getLastFileResults();
    if (!lastPayload) {
      decorationService.refreshVisibleEditors();
    }
    return {
      scanSession: this._scanSession,
      rules: this._ruleService.getRules(),
      settings: this._buildSettings(),
      summary: this._scanResults.size > 0 ? this._buildSummary() : null,
      activeFileData: lastPayload ?? null,
    };
  }

  private _sendSnapshot(): void {
    this._postMessage({
      type: 'stateSnapshot',
      snapshot: this.buildStateSnapshot(),
    });
  }

  private _sendSettingsUpdate(settings: Partial<SettingsState>): void {
    this._postMessage({
      type: 'settingsUpdate',
      settings,
    });
  }

  public prepareForScan(sessionId: number): void {
    this._cancelAllRevalidations();
    this._scanResults.clear();
    this._validatingRuleIds.clear();
    this._validatingMatchValues.clear();
    this._lastDuration = undefined;
    this._lastQueryParams = undefined;
    this._queryVersion = 0;
    this._queryVersionKey = '';
    this._lastRuleResultsPushAt = 0;
    this._matchIndexDirty = true;
    this._scanSession = {
      sessionId,
      phase: 'scanning',
      viewState: 'landing',
      hasResults: false,
    };
    this._postMessage({ type: 'clearResults' });
    this._postMessage({ type: 'scanSession', session: this._scanSession });
  }

  public sendScanSession(session: ScanSessionState): void {
    this._scanSession = session;
    this._postMessage({
      type: 'scanSession',
      session: this._scanSession,
    });
  }

  private _buildSummary(): ScanSummary {
    const workspaceRoots = vscode.workspace.workspaceFolders?.map((f) => f.uri.fsPath) || [];
    const groupMap = new Map<
      string,
      Map<string, { ruleId: string; color: string; count: number }>
    >();

    for (const [groupName, results] of this._scanResults) {
      let ruleMap = groupMap.get(groupName);
      if (!ruleMap) {
        ruleMap = new Map();
        groupMap.set(groupName, ruleMap);
      }
      for (const r of results) {
        const ruleName = r.ruleName || 'Unknown Rule';
        const existing = ruleMap.get(ruleName);
        if (existing) {
          existing.count++;
        } else {
          ruleMap.set(ruleName, { ruleId: r.ruleId, color: r.color || 'gray', count: 1 });
        }
      }
    }

    const groups: GroupSummary[] = [];
    for (const [name, ruleMap] of groupMap) {
      const rules: RuleSummary[] = [];
      for (const [ruleName, info] of ruleMap) {
        rules.push({ ruleId: info.ruleId, name: ruleName, color: info.color, count: info.count });
      }
      groups.push({ name, rules });
    }

    return {
      groups,
      duration: this._lastDuration,
      validatingRuleIds: Array.from(this._validatingRuleIds),
      validatingMatchValues: Array.from(this._validatingMatchValues),
      workspaceRoots,
    };
  }

  private _sendSummary(): void {
    this._postMessage({
      type: 'scanSummary',
      summary: this._buildSummary(),
    });
  }

  private _ensureMatchIndex(groupName: string, ruleName: string): void {
    const key = `${groupName}|${ruleName}`;
    if (!this._matchIndexDirty && this._matchIndexKey === key) {
      return;
    }
    this._matchIndex.clear();
    const groupResults = this._scanResults.get(groupName) || [];
    for (const r of groupResults) {
      if ((r.ruleName || 'Unknown Rule') !== ruleName) continue;
      const matchValue = r.match || '';
      let entry = this._matchIndex.get(matchValue);
      if (!entry) {
        entry = {
          results: [],
          severity: r.severity || 'none',
          color: r.color || 'gray',
          ruleId: r.ruleId,
        };
        this._matchIndex.set(matchValue, entry);
      }
      entry.results.push(r);
    }
    this._matchIndexKey = key;
    this._matchIndexDirty = false;
  }

  private static readonly _SEVERITY_RANK: Record<string, number> = {
    high: 0,
    medium: 1,
    low: 2,
    none: 3,
  };

  private _buildSearchFilter(
    params: QueryRuleResultsParams
  ): { searchRegex: RegExp | null; searchTerm: string | null } | false {
    if (!params.searchTerm) {
      return { searchRegex: null, searchTerm: null };
    }
    if (params.useRegex) {
      try {
        return { searchRegex: new RegExp(params.searchTerm, 'i'), searchTerm: null };
      } catch {
        return false;
      }
    }
    return { searchRegex: null, searchTerm: params.searchTerm.toLowerCase() };
  }

  private _buildQueryVersionKey(params: QueryRuleResultsParams): string {
    const severities = params.severities ? [...params.severities].sort().join(',') : '';
    return `${params.groupName}|${params.ruleName}|${params.searchTerm || ''}|${params.useRegex ? '1' : '0'}|${severities}`;
  }

  private _cloneQueryParams(params: QueryRuleResultsParams): QueryRuleResultsParams {
    return {
      groupName: params.groupName,
      ruleName: params.ruleName,
      searchTerm: params.searchTerm,
      useRegex: params.useRegex,
      severities: params.severities ? [...params.severities] : undefined,
    };
  }

  private _publishActiveQueryIfNeeded(): void {
    if (!this._lastQueryParams) {
      return;
    }

    const validationActive =
      this._validatingRuleIds.size > 0 || this._validatingMatchValues.size > 0;
    if (validationActive) {
      const now = Date.now();
      if (
        now - this._lastRuleResultsPushAt <
        CONFIG_LIMITS.VALIDATION_RULE_RESULTS_REFRESH_MIN_INTERVAL
      ) {
        return;
      }
      this._lastRuleResultsPushAt = now;
    } else {
      this._lastRuleResultsPushAt = Date.now();
    }

    this.queryRuleResults(this._lastQueryParams);
  }

  private _countMatchIndexResults(): number {
    let totalResults = 0;
    for (const entry of this._matchIndex.values()) {
      totalResults += entry.results.length;
    }
    return totalResults;
  }

  private _collectRuleMatches(
    searchRegex: RegExp | null,
    searchTerm: string | null,
    sevSet: Set<Severity> | null
  ): { matches: MatchSummary[]; filteredResults: number } {
    const matches: MatchSummary[] = [];
    let filteredResults = 0;

    for (const [matchValue, entry] of this._matchIndex) {
      if (searchRegex && !searchRegex.test(matchValue)) continue;
      if (searchTerm && !matchValue.toLowerCase().includes(searchTerm)) continue;

      let count: number;
      if (sevSet) {
        count = 0;
        for (const r of entry.results) {
          if (sevSet.has(r.severity || 'none')) count++;
        }
        if (count === 0) continue;
      } else {
        count = entry.results.length;
      }

      filteredResults += count;
      matches.push({
        match: matchValue,
        count,
        severity: entry.severity,
        color: entry.color as RuleColor,
        ruleId: entry.ruleId,
      });
    }

    return { matches, filteredResults };
  }

  private _sortMatchesBySeverity(matches: MatchSummary[]): void {
    const rank = DataboardProvider._SEVERITY_RANK;
    matches.sort((a, b) => {
      const ar = rank[a.severity] ?? 3;
      const br = rank[b.severity] ?? 3;
      if (ar !== br) return ar - br;
      return a.match.localeCompare(b.match);
    });
  }

  private _postRuleResults(
    params: QueryRuleResultsParams,
    matches: MatchSummary[],
    filteredResults: number,
    totalResults: number
  ): void {
    this._sortMatchesBySeverity(matches);

    const totalMatches = matches.length;

    this._postMessage({
      type: 'ruleResults',
      ruleResults: {
        groupName: params.groupName,
        ruleName: params.ruleName,
        matches,
        totalMatches,
        filteredResults,
        totalResults,
        queryVersion: this._queryVersion,
      },
    });
  }

  public queryRuleResults(params: QueryRuleResultsParams): void {
    const queryVersionKey = this._buildQueryVersionKey(params);
    if (queryVersionKey !== this._queryVersionKey) {
      this._queryVersionKey = queryVersionKey;
      this._queryVersion++;
    }
    this._lastQueryParams = this._cloneQueryParams(params);
    this._ensureMatchIndex(params.groupName, params.ruleName);

    const totalResults = this._countMatchIndexResults();

    const searchFilter = this._buildSearchFilter(params);
    if (searchFilter === false) {
      this._postRuleResults(params, [], 0, totalResults);
      return;
    }
    const sevSet = params.severities ? new Set(params.severities) : null;
    const { matches, filteredResults } = this._collectRuleMatches(
      searchFilter.searchRegex,
      searchFilter.searchTerm,
      sevSet
    );
    this._postRuleResults(params, matches, filteredResults, totalResults);
  }

  public queryMatchFiles(groupName: string, ruleName: string, matchValues: string[]): void {
    this._ensureMatchIndex(groupName, ruleName);
    const matchesCurrentQuery =
      this._lastQueryParams?.groupName === groupName && this._lastQueryParams.ruleName === ruleName;
    const sevSet =
      matchesCurrentQuery && this._lastQueryParams?.severities
        ? new Set(this._lastQueryParams.severities)
        : null;

    for (const matchValue of matchValues) {
      const entry = this._matchIndex.get(matchValue);
      const files: FileHit[] = [];
      if (entry) {
        for (const r of entry.results) {
          if (sevSet && !sevSet.has(r.severity || 'none')) continue;
          files.push({
            file: r.file,
            line: r.line,
            column: r.column,
            severity: r.severity || 'none',
          });
        }
      }
      this._postMessage({
        type: 'matchFiles',
        matchFiles: {
          groupName,
          ruleName,
          matchValue,
          files,
          queryVersion: this._queryVersion,
        },
      });
    }
  }

  private async _rescan(): Promise<void> {
    if (!this._lastScanPaths || this._lastScanPaths.length === 0) {
      await vscode.commands.executeCommand('hae.scanWorkspace');
      return;
    }

    const validPaths: string[] = [];
    for (const p of this._lastScanPaths) {
      try {
        await vscode.workspace.fs.stat(vscode.Uri.file(p));
        validPaths.push(p);
      } catch {
        Logger.warn(`Rescan: path no longer exists: ${p}`);
      }
    }

    if (validPaths.length === 0) {
      notify.warning('Rescan failed', 'All previous scan paths no longer exist');
      this._lastScanPaths = undefined;
      await vscode.commands.executeCommand('hae.scanWorkspace');
      return;
    }

    if (validPaths.length === 1) {
      await vscode.commands.executeCommand('hae.scanFolder', vscode.Uri.file(validPaths[0]));
    } else {
      await vscode.commands.executeCommand('hae.scanWorkspace');
    }
  }

  private async _cancelScan(): Promise<void> {
    await vscode.commands.executeCommand('hae.cancelScan');
  }

  private _revalidate(ruleIds: string[], matchValues?: string[]): void {
    if (this._scanResults.size === 0) {
      return;
    }

    const rules = this._ruleService
      .getRules()
      .filter((r) => ruleIds.includes(r.id) && r.validator?.command);
    if (rules.length === 0) {
      return;
    }

    const selection = this._selectRevalidateResults(ruleIds, matchValues);
    if (!selection) {
      return;
    }

    const rule = rules[0];
    const title = this._buildRevalidateTitle(rule.name, selection.isPartial, matchValues);

    const jobController = JobController.getInstance();
    const revalidateJob = jobController.startJob('revalidate', {
      label: title,
    });
    if (!revalidateJob) {
      this._notifyRevalidateSkipped(jobController);
      return;
    }

    this._setRevalidatingFlags(selection.ownedMatchValues, selection.ownedRuleIds);

    const token = revalidateJob.token;

    void vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title,
        cancellable: true,
      },
      async (_progress, progressToken) => {
        const progressCancellation = progressToken.onCancellationRequested(() => {
          revalidateJob.cancel();
        });

        try {
          const scanService = ScanService.getInstance();
          await scanService.runValidators(selection.resultsToValidate, rules, token, () => {
            if (token.isCancellationRequested) return;
            this.updateResults(this._scanResults);
            if (this._onSeverityChanged) {
              this._onSeverityChanged(this._scanResults);
            }
          });
        } finally {
          this._clearRevalidatingFlags(selection.ownedMatchValues, selection.ownedRuleIds);
          revalidateJob.complete();
          progressCancellation.dispose();
          this.updateResults(this._scanResults);
        }
      }
    );
  }

  private _selectRevalidateResults(
    ruleIds: string[],
    matchValues?: string[]
  ):
    | {
        resultsToValidate: Map<string, ScanResult[]>;
        isPartial: boolean;
        ownedMatchValues: Set<string>;
        ownedRuleIds: Set<string>;
      }
    | undefined {
    const isPartial = !!(matchValues && matchValues.length > 0);
    if (!isPartial) {
      return {
        resultsToValidate: this._scanResults,
        isPartial: false,
        ownedMatchValues: new Set<string>(),
        ownedRuleIds: new Set(ruleIds),
      };
    }

    const matchSet = new Set(matchValues);
    const resultsToValidate = new Map<string, ScanResult[]>();
    for (const [file, fileResults] of this._scanResults) {
      const filtered = fileResults.filter(
        (r) => ruleIds.includes(r.ruleId) && matchSet.has(r.match)
      );
      if (filtered.length > 0) {
        resultsToValidate.set(file, filtered);
      }
    }

    if (resultsToValidate.size === 0) {
      return undefined;
    }

    return {
      resultsToValidate,
      isPartial: true,
      ownedMatchValues: new Set(matchValues),
      ownedRuleIds: new Set<string>(),
    };
  }

  private _buildRevalidateTitle(
    ruleName: string,
    isPartial: boolean,
    matchValues?: string[]
  ): string {
    if (!isPartial || !matchValues || matchValues.length === 0) {
      return `Validating rule: ${ruleName}`;
    }

    return `Validating [${ruleName}]: ${matchValues.join(', ').slice(0, 50)}`;
  }

  private _notifyRevalidateSkipped(jobController: JobController): void {
    if (jobController.hasActiveKind('scan')) {
      notify.info('Validation skipped', 'Scan is running, please retry after scan completes');
      return;
    }

    notify.info('Validation skipped', 'Another validation task is still running');
  }

  private _setRevalidatingFlags(matchValues: Set<string>, ruleIds: Set<string>): void {
    for (const value of matchValues) {
      this._validatingMatchValues.add(value);
    }
    for (const id of ruleIds) {
      this._validatingRuleIds.add(id);
    }
  }

  private _clearRevalidatingFlags(matchValues: Set<string>, ruleIds: Set<string>): void {
    for (const value of matchValues) {
      this._validatingMatchValues.delete(value);
    }
    for (const id of ruleIds) {
      this._validatingRuleIds.delete(id);
    }
  }

  private _cancelAllRevalidations(): void {
    JobController.getInstance().cancelKind('revalidate', 'cancel-all-revalidations');
  }

  public getIgnoredExtensions(): string[] {
    return this._configService.getIgnoredExtensions();
  }

  public switchToSettings(): void {
    this._postMessage({
      type: 'viewAction',
      action: 'showSettings',
    });
  }

  public switchToResults(): void {
    this._postMessage({
      type: 'viewAction',
      action: 'showResults',
    });
  }

  public hasResults(): boolean {
    return this._scanResults.size > 0;
  }

  public updateResults(
    results: Map<string, ScanResult[]>,
    duration?: number,
    scanPaths?: string[],
    validatingRuleIds?: string[]
  ): void {
    this._scanResults = results;
    this._matchIndexDirty = true;
    this._scanSession = {
      ...this._scanSession,
      hasResults: this._scanResults.size > 0,
      viewState: this._scanResults.size > 0 ? 'results' : this._scanSession.viewState,
    };
    if (scanPaths && scanPaths.length > 0) {
      this._lastScanPaths = scanPaths;
    }
    if (duration !== undefined) {
      this._lastDuration = duration;
    }
    if (validatingRuleIds !== undefined) {
      this._validatingRuleIds = new Set(validatingRuleIds);
    }
    if (this._view) {
      try {
        this._postMessage({ type: 'scanSession', session: this._scanSession });
        this._sendSummary();
        this._publishActiveQueryIfNeeded();
      } catch (error) {
        Logger.error(
          'Failed to update panel with scan results. The results may be too large.',
          error
        );
      }
    }
  }

  public clearResults(): void {
    this._cancelAllRevalidations();
    this._scanResults.clear();
    this._validatingRuleIds.clear();
    this._validatingMatchValues.clear();
    this._lastDuration = undefined;
    this._lastQueryParams = undefined;
    this._queryVersion = 0;
    this._queryVersionKey = '';
    this._lastRuleResultsPushAt = 0;
    this._matchIndexDirty = true;
    this._scanSession = {
      ...this._scanSession,
      phase: 'idle',
      viewState: 'landing',
      hasResults: false,
    };
    this._postMessage({ type: 'scanSession', session: this._scanSession });
    void vscode.commands.executeCommand('hae.clearStoredResults');
    this._postMessage({ type: 'clearResults' });
  }

  public sendActiveFilePayload(payload: ActiveFilePayload): void {
    if (this._view) {
      this._postMessage({
        type: 'activeFileResults',
        data: payload,
      });
    }
  }

  public onSeverityChanged(callback: (results: Map<string, ScanResult[]>) => void): void {
    this._onSeverityChanged = callback;
  }

  private _updateSeverity(file: string, line: number, column: number, severity: Severity): void {
    for (const [, results] of this._scanResults) {
      for (const result of results) {
        if (result.file === file && result.line === line && result.column === column) {
          result.severity = severity;
        }
      }
    }
    this._matchIndexDirty = true;

    if (this._onSeverityChanged) {
      this._onSeverityChanged(this._scanResults);
    }

    this._sendSummary();

    if (this._lastQueryParams) {
      this.queryRuleResults(this._lastQueryParams);
    }
  }

  private _updateMatchSeverity(
    groupName: string,
    ruleName: string,
    matchValue: string,
    severity: Severity
  ): void {
    const groupResults = this._scanResults.get(groupName);
    if (!groupResults) return;

    for (const result of groupResults) {
      if ((result.ruleName || 'Unknown Rule') === ruleName && result.match === matchValue) {
        result.severity = severity;
      }
    }
    this._matchIndexDirty = true;

    if (this._onSeverityChanged) {
      this._onSeverityChanged(this._scanResults);
    }

    this._sendSummary();

    if (this._lastQueryParams) {
      this.queryRuleResults(this._lastQueryParams);
    }
  }

  private _getHtml(webview: vscode.Webview): string {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'webview-ui', 'dist', 'assets', 'main.js')
    );
    const styleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'webview-ui', 'dist', 'assets', 'main.css')
    );
    const baseStyleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'webview-ui', 'dist', 'assets', 'base.css')
    );
    const logoUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'resources', 'images', 'logo.png')
    );

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; font-src ${webview.cspSource}; script-src ${webview.cspSource}; img-src ${webview.cspSource};">
    <title>HaE</title>
    <link rel="stylesheet" href="${baseStyleUri}">
    <link rel="stylesheet" href="${styleUri}">
</head>
<body>
    <div id="root" data-logo-uri="${logoUri}"></div>
    <script type="module" src="${scriptUri}"></script>
</body>
</html>`;
  }
}
