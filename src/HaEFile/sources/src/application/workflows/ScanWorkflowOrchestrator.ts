import * as vscode from 'vscode';
import { DataboardViewState, ScanResult, ScanRule, ScanSessionPhase } from '../../types';
import { JobController, RuleService, ScanResultsPersistQueue, ScanService } from '../../services';
import { createScopedNotifier, Logger } from '../../utils/logger';
import { DataboardProvider } from '../../webviews';

const notify = createScopedNotifier('Extension');

interface ScanExecutionState {
  totalDuration: number;
  scanCompleted: boolean;
  scanHasResults: boolean;
  hasPublishedResultsThisRun: boolean;
}

interface ScanPipelineContext {
  paths: string[];
  rules: ScanRule[];
  ignoredExtensions: string[];
  cancellationToken: vscode.CancellationToken;
  allResults: Map<string, ScanResult[]>;
  emitSession: (
    phase: ScanSessionPhase,
    viewState: DataboardViewState,
    hasResults: boolean
  ) => void;
  state: ScanExecutionState;
  progress: vscode.Progress<{ message?: string; increment?: number }>;
}

export class ScanWorkflowOrchestrator {
  private scanSessionSeed = 0;

  private activeScanStopHandler?: () => void;

  constructor(
    private readonly provider: DataboardProvider,
    private readonly ruleService: RuleService,
    private readonly scanService: ScanService,
    private readonly persistQueue: ScanResultsPersistQueue
  ) {}

  async scanPaths(paths: string[], displayName: string): Promise<void> {
    await this.performScanInternal(paths, displayName);
  }

  async scanWorkspace(folders: readonly vscode.WorkspaceFolder[]): Promise<void> {
    const displayName = folders.map((f) => f.name).join(', ');
    const paths = folders.map((f) => f.uri.fsPath);
    await this.performScanInternal(paths, displayName);
  }

  cancelOrClear(): void {
    if (this.activeScanStopHandler) {
      this.activeScanStopHandler();
      return;
    }

    const jobController = JobController.getInstance();
    if (jobController.hasActiveJobs()) {
      jobController.cancelAll('cancel-command');
      this.scanService.cancelActiveScans();
      return;
    }

    this.provider.clearResults();
    this.provider.sendScanSession({
      sessionId: this.scanSessionSeed,
      phase: 'idle',
      viewState: 'landing',
      hasResults: false,
    });
  }

  dispose(): void {
    this.activeScanStopHandler = undefined;
  }

  private async validateScanPreconditions(): Promise<
    { rules: ScanRule[]; ignoredExtensions: string[] } | undefined
  > {
    if (JobController.getInstance().hasActiveKind('scan')) {
      notify.warning('Scan already in progress', 'Stop current scan before starting another one');
      return undefined;
    }

    const rules = this.ruleService.getEnabledRules();
    if (rules.length === 0) {
      notify.warning('Scan failed', 'No enabled rules found, please configure rules first');
      return undefined;
    }

    if (this.provider.hasResults()) {
      const answer = await vscode.window.showWarningMessage(
        'Scanning will overwrite the current results. Continue?',
        { modal: true },
        'Scan'
      );
      if (answer !== 'Scan') {
        return undefined;
      }
    }

    return { rules, ignoredExtensions: this.provider.getIgnoredExtensions() };
  }

  private mergeResults(target: Map<string, ScanResult[]>, source: Map<string, ScanResult[]>): void {
    for (const [groupName, groupResults] of source) {
      const existing = target.get(groupName) || [];
      const indexByKey = new Map<string, number>();
      existing.forEach((r, idx) =>
        indexByKey.set(`${r.file}:${r.line}:${r.column}:${r.ruleId}:${r.match}`, idx)
      );

      for (const result of groupResults) {
        const key = `${result.file}:${result.line}:${result.column}:${result.ruleId}:${result.match}`;
        const existingIndex = indexByKey.get(key);
        if (existingIndex !== undefined) {
          existing[existingIndex] = { ...existing[existingIndex], ...result };
        } else {
          existing.push(result);
          indexByKey.set(key, existing.length - 1);
        }
      }

      target.set(groupName, existing);
    }
  }

  private hasAnyResults(results: Map<string, ScanResult[]>): boolean {
    for (const groupResults of results.values()) {
      if (groupResults.length > 0) {
        return true;
      }
    }

    return false;
  }

  private async executeScanPipeline(context: ScanPipelineContext): Promise<void> {
    const {
      paths,
      rules,
      ignoredExtensions,
      cancellationToken,
      allResults,
      emitSession,
      state,
      progress,
    } = context;

    progress.report({ increment: 0, message: 'Starting scan...' });
    const progressPerPath = paths.length > 1 ? 70 / paths.length : 70;

    for (let i = 0; i < paths.length; i++) {
      if (cancellationToken.isCancellationRequested) return;

      const progressMessage =
        paths.length > 1 ? `Scanning (${i + 1}/${paths.length})...` : 'Scanning...';
      progress.report({ increment: 0, message: progressMessage });

      const results = await this.scanService.scanPath(
        paths[i],
        rules,
        ignoredExtensions,
        cancellationToken,
        (_partial, scanDuration) => {
          state.totalDuration += scanDuration;
        }
      );

      if (cancellationToken.isCancellationRequested) return;
      this.mergeResults(allResults, results);
      progress.report({ increment: progressPerPath });
    }

    if (cancellationToken.isCancellationRequested) return;

    state.scanHasResults = this.hasAnyResults(allResults);
    if (!state.scanHasResults) {
      this.provider.clearResults();
      notify.info('Scan completed', 'No matches found');
      state.scanCompleted = true;

      return;
    }

    this.provider.updateResults(allResults, state.totalDuration, paths, []);
    await this.persistQueue.flushNow(allResults, state.totalDuration);
    state.hasPublishedResultsThisRun = true;
    emitSession('validating', 'results', true);

    progress.report({ increment: 20, message: 'Validating results...' });
    await this.scanService.runValidators(
      allResults,
      rules,
      cancellationToken,
      (_results, validatingRuleIds) => {
        if (cancellationToken.isCancellationRequested) return;
        this.provider.updateResults(allResults, undefined, undefined, validatingRuleIds ?? []);
        this.persistQueue.enqueue(allResults, state.totalDuration);
      }
    );

    if (cancellationToken.isCancellationRequested) return;

    this.provider.updateResults(allResults, state.totalDuration, paths, []);
    await this.persistQueue.flushNow(allResults, state.totalDuration);
    state.scanCompleted = true;
  }

  private async performScanInternal(paths: string[], displayName: string): Promise<void> {
    const preconditions = await this.validateScanPreconditions();
    if (!preconditions) {
      return;
    }

    const { rules, ignoredExtensions } = preconditions;

    const jobController = JobController.getInstance();
    const scanJob = jobController.startJob('scan', {
      label: displayName,
      preemptLowerPriority: true,
    });

    if (!scanJob) {
      notify.warning('Scan already in progress', 'Stop current scan before starting another one');
      return;
    }

    this.persistQueue.setMetadata(paths, displayName);

    const sessionId = ++this.scanSessionSeed;
    const allResults = new Map<string, ScanResult[]>();
    const state: ScanExecutionState = {
      totalDuration: 0,
      scanCompleted: false,
      scanHasResults: false,
      hasPublishedResultsThisRun: false,
    };

    const emitSession = (
      phase: ScanSessionPhase,
      viewState: DataboardViewState,
      hasResults: boolean
    ) => {
      this.provider.sendScanSession({
        sessionId,
        phase,
        viewState,
        hasResults,
      });
    };

    const cancellationToken = scanJob.token;

    let cancelResolve!: () => void;
    const cancelBarrier = new Promise<void>((resolve) => {
      cancelResolve = resolve;
    });

    const requestStop = () => {
      if (cancellationToken.isCancellationRequested) {
        return;
      }

      const hasVisibleResults = state.hasPublishedResultsThisRun;
      const targetViewState: DataboardViewState = hasVisibleResults ? 'results' : 'landing';
      emitSession('idle', targetViewState, hasVisibleResults);
      jobController.cancelAll('scan-stop');
      this.scanService.cancelActiveScans();
      cancelResolve();
    };

    this.activeScanStopHandler = requestStop;
    this.provider.prepareForScan(sessionId);

    try {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title:
            paths.length > 1 ? `Scanning workspace: ${displayName}` : `Scanning ${displayName}`,
          cancellable: true,
        },
        async (progress, token) => {
          const progressCancellation = token.onCancellationRequested(requestStop);
          const guardedBody = this.executeScanPipeline({
            paths,
            rules,
            ignoredExtensions,
            cancellationToken,
            allResults,
            emitSession,
            state,
            progress,
          }).catch((error) => {
            if (!cancellationToken.isCancellationRequested) {
              throw error;
            }
            Logger.debug('Background scan cleanup after cancel', error);
          });

          try {
            await Promise.race([guardedBody, cancelBarrier]);
          } finally {
            progressCancellation.dispose();
          }
        }
      );

      if (cancellationToken.isCancellationRequested) {
        if (state.hasPublishedResultsThisRun) {
          this.provider.updateResults(allResults, state.totalDuration, paths, []);
          await this.persistQueue.flushNow(allResults, state.totalDuration);
        }
      } else if (state.scanCompleted && state.scanHasResults) {
        emitSession('idle', 'results', true);
      }
    } catch (error) {
      Logger.error('Scan workflow failed unexpectedly', error);
      if (cancellationToken.isCancellationRequested && state.hasPublishedResultsThisRun) {
        this.provider.updateResults(allResults, state.totalDuration, paths, []);
        await this.persistQueue.flushNow(allResults, state.totalDuration);
      }
      if (!cancellationToken.isCancellationRequested) {
        const hasVisibleResults = state.hasPublishedResultsThisRun || this.provider.hasResults();
        const targetViewState: DataboardViewState = hasVisibleResults ? 'results' : 'landing';
        emitSession('idle', targetViewState, hasVisibleResults);
        notify.error('Scan failed', 'Scan ended unexpectedly');
      }
    } finally {
      if (this.activeScanStopHandler === requestStop) {
        this.activeScanStopHandler = undefined;
      }
      scanJob.complete();
    }
  }
}
