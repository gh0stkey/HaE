import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { spawn } from 'child_process';
import { Worker } from 'worker_threads';
import { ScanRule, ScanResult, RipgrepConfig, CONFIG_DEFAULTS, CONFIG_LIMITS } from '../../types';
import { ConfigService } from '../config/ConfigService';
import { ValidatorService } from '../validation/ValidatorService';
import { createScopedLogger, createScopedNotifier } from '../../utils/logger';
import { chunkArray, groupRulesByPattern } from '../../utils/array';
import type { WorkerOutbound, ScanWorkerRequest } from './ScanWorker';

const logger = createScopedLogger('ScanService');
const notify = createScopedNotifier('Scan');

export class ScanService {
  private static instance: ScanService | null = null;

  private disposed = false;

  private config!: RipgrepConfig;

  private configService: ConfigService;

  private disposables: vscode.Disposable[] = [];

  private activeWorkers: Set<Worker> = new Set();

  private constructor() {
    this.configService = ConfigService.getInstance();
    this.loadConfig();
    this.disposables.push(
      this.configService.onConfigChange(() => {
        this.loadConfig();
      })
    );
  }

  static getInstance(): ScanService {
    if (ScanService.instance === null || ScanService.instance.disposed) {
      ScanService.instance = new ScanService();
    }

    return ScanService.instance;
  }

  private loadConfig(): void {
    const configuredPath = this.configService.getRipgrepPath();
    this.config = {
      path: configuredPath || this.getDefaultRipgrepPath(),
      maxResults: this.configService.getMaxResults(),
      scanWorkerMaxConcurrency: this.configService.getScanWorkerMaxConcurrency(),
    };
  }

  async testRipgrepPath(): Promise<boolean> {
    return this.testRipgrepPathWithCustomPath(this.config.path);
  }

  private getBuiltInRipgrepPath(): string | null {
    const appRoot = vscode.env.appRoot;
    const rgName = process.platform === 'win32' ? 'rg.exe' : 'rg';

    const possiblePaths = [
      path.join(appRoot, 'node_modules', '@vscode', 'ripgrep', 'bin', rgName),
      path.join(appRoot, 'node_modules.asar.unpacked', '@vscode', 'ripgrep', 'bin', rgName),
      path.join(appRoot, 'node_modules', 'vscode-ripgrep', 'bin', rgName),
      path.join(appRoot, 'node_modules.asar.unpacked', 'vscode-ripgrep', 'bin', rgName),
    ];

    for (const rgPath of possiblePaths) {
      if (fs.existsSync(rgPath)) {
        logger.info(`Found built-in ripgrep at: ${rgPath}`);

        return rgPath;
      }
    }

    logger.warn('Built-in ripgrep not found, will try system rg');

    return null;
  }

  private getDefaultRipgrepPath(): string {
    return this.getBuiltInRipgrepPath() || 'rg';
  }

  async testRipgrepPathWithCustomPath(customPath: string): Promise<boolean> {
    const testPath = customPath || this.getDefaultRipgrepPath();

    return this.isValidRipgrepPath(testPath);
  }

  async setRipgrepPath(newPath: string): Promise<boolean> {
    const normalizedPath = newPath.trim();
    const useDefaultPath = normalizedPath.length === 0;
    const testPath = useDefaultPath ? this.getDefaultRipgrepPath() : normalizedPath;
    const isValid = await this.isValidRipgrepPath(testPath);

    if (isValid) {
      this.config.path = testPath;
      try {
        await this.configService.setRipgrepPath(useDefaultPath ? '' : normalizedPath);

        return true;
      } catch {
        return false;
      }
    } else {
      notify.error('Validate ripgrep path failed', undefined, 'Invalid ripgrep executable');

      return false;
    }
  }

  private isValidRipgrepPath(rgPath: string): Promise<boolean> {
    return new Promise((resolve) => {
      try {
        const child = spawn(rgPath, ['--version']);

        child.on('error', (_error) => {
          logger.warn('Ripgrep path test failed');
          resolve(false);
        });

        child.on('exit', (code) => {
          resolve(code === 0);
        });
      } catch {
        logger.warn('Failed to spawn ripgrep');
        resolve(false);
      }
    });
  }

  async scanPath(
    targetPath: string,
    rules: ScanRule[],
    ignoredExtensions: string[] = [],
    token?: vscode.CancellationToken,
    onScanComplete?: (results: Map<string, ScanResult[]>, scanDuration: number) => void
  ): Promise<Map<string, ScanResult[]>> {
    const results = new Map<string, ScanResult[]>();
    const scanStartTime = Date.now();
    if (token?.isCancellationRequested) {
      logger.info('Scan cancelled before starting');

      return results;
    }
    if (!(await this.testRipgrepPath())) {
      notify.error(
        'Scan failed',
        undefined,
        'Ripgrep is not available, please check configuration'
      );

      return results;
    }
    const loadedRules = rules.filter((r) => r.loaded);
    if (loadedRules.length === 0) {
      logger.warn('No loaded rules found. All rules are disabled.');

      return results;
    }

    const rulesByKey = groupRulesByPattern(loadedRules);
    const configuredConcurrency = this.config.scanWorkerMaxConcurrency;
    const normalizedConcurrency =
      Number.isFinite(configuredConcurrency) && configuredConcurrency >= 1
        ? Math.floor(configuredConcurrency)
        : CONFIG_DEFAULTS.SCAN_WORKER_MAX_CONCURRENCY;
    const concurrency = Math.max(
      CONFIG_LIMITS.SCAN_WORKER_MAX_CONCURRENCY_MIN,
      normalizedConcurrency
    );
    const entries = [...rulesByKey.entries()];
    const chunks = chunkArray(entries, concurrency);
    logger.info(
      `Parallel scan: ${entries.length} patterns, ${concurrency} concurrency, ${chunks.length} batches`
    );

    for (const chunk of chunks) {
      if (token?.isCancellationRequested) {
        this.cancelActiveScans();
        logger.info('Scan cancelled during execution');

        return results;
      }

      const tasks = chunk.map(async ([key, patternRules]) => {
        const [pattern, sensitiveStr] = key.split('::');
        const isSensitive = sensitiveStr === 'true';
        try {
          await this.scanWithPattern({
            targetPath,
            pattern,
            sensitive: isSensitive,
            ignoredExtensions,
            onResultBatch: (batch) => {
              this.distributeResultsToRules(batch, patternRules, results);
            },
            token,
          });
        } catch (error) {
          if (!token?.isCancellationRequested) {
            logger.error(
              `Error scanning with pattern "${pattern}" (${isSensitive ? 'case-sensitive' : 'case-insensitive'})`,
              error
            );
          }
        }
      });

      await Promise.all(tasks);
    }

    const scanDuration = Date.now() - scanStartTime;
    onScanComplete?.(results, scanDuration);

    return results;
  }

  public cancelActiveScans(): void {
    const count = this.activeWorkers.size;
    if (count > 0) {
      logger.info(`Terminating ${count} active scan workers`);
      for (const worker of Array.from(this.activeWorkers)) {
        try {
          worker.postMessage({ type: 'cancel' });
          void worker.terminate();
        } catch {}
      }
      this.activeWorkers.clear();
    }
  }

  public async runValidators(
    results: Map<string, ScanResult[]>,
    rules: ScanRule[],
    token?: vscode.CancellationToken,
    onPartialValidation?: (results: Map<string, ScanResult[]>, validatingRuleIds?: string[]) => void
  ): Promise<void> {
    const validatorService = ValidatorService.getInstance();
    const resultsByRule = new Map<string, ScanResult[]>();
    for (const [, groupResults] of results) {
      for (const result of groupResults) {
        if (!resultsByRule.has(result.ruleId)) {
          resultsByRule.set(result.ruleId, []);
        }
        resultsByRule.get(result.ruleId)!.push(result);
      }
    }

    const validatingRuleIds = new Set<string>();
    let updatesSinceLastPush = 0;
    const VALIDATION_UPDATE_STRIDE = 256;

    let pendingUpdate = false;
    let lastUpdateTime = 0;
    const UI_UPDATE_INTERVAL = CONFIG_DEFAULTS.UI_UPDATE_INTERVAL;
    const throttledUpdate = () => {
      const now = Date.now();
      if (now - lastUpdateTime >= UI_UPDATE_INTERVAL) {
        lastUpdateTime = now;
        try {
          onPartialValidation?.(results, Array.from(validatingRuleIds));
        } catch (error) {
          logger.debug('UI callback error during throttled update:', error);
        }
        pendingUpdate = false;
      } else if (!pendingUpdate) {
        pendingUpdate = true;
        setTimeout(
          () => {
            pendingUpdate = false;
            lastUpdateTime = Date.now();
            try {
              onPartialValidation?.(results, Array.from(validatingRuleIds));
            } catch (error) {
              logger.debug('UI callback error during delayed update:', error);
            }
          },
          UI_UPDATE_INTERVAL - (now - lastUpdateTime)
        );
      }
    };
    const validationTasks: Promise<void>[] = [];
    for (const rule of rules) {
      if (token?.isCancellationRequested) break;
      if (!rule.validator?.command) continue;
      const ruleResults = resultsByRule.get(rule.id);
      if (!ruleResults || ruleResults.length === 0) continue;

      validatingRuleIds.add(rule.id);

      const task = validatorService
        .validateAsyncDeduped(rule, ruleResults, token, () => {
          if (token?.isCancellationRequested) {
            return;
          }
          updatesSinceLastPush++;
          if (updatesSinceLastPush >= VALIDATION_UPDATE_STRIDE) {
            updatesSinceLastPush = 0;
            throttledUpdate();
          }
        })
        .finally(() => {
          updatesSinceLastPush = 0;
          validatingRuleIds.delete(rule.id);
          throttledUpdate();
        });
      validationTasks.push(task);
    }

    if (validatingRuleIds.size > 0) {
      onPartialValidation?.(results, Array.from(validatingRuleIds));
    }

    await Promise.all(validationTasks);
    try {
      onPartialValidation?.(results, []);
    } catch (error) {
      logger.debug('UI callback error during final update:', error);
    }
  }

  private distributeResultsToRules(
    patternResults: Omit<ScanResult, 'ruleId' | 'ruleName'>[],
    patternRules: ScanRule[],
    results: Map<string, ScanResult[]>
  ): void {
    for (const result of patternResults) {
      for (const rule of patternRules) {
        if (!results.has(rule.group)) {
          results.set(rule.group, []);
        }
        const scanResult: ScanResult = {
          ...result,
          ruleId: rule.id,
          ruleName: rule.name,
          color: rule.color,
        };
        results.get(rule.group)!.push(scanResult);
      }
    }
  }

  private async scanWithPattern(options: {
    targetPath: string;
    pattern: string;
    sensitive?: boolean;
    ignoredExtensions?: string[];
    onResultBatch?: (batch: Omit<ScanResult, 'ruleId' | 'ruleName'>[]) => void;
    token?: vscode.CancellationToken;
  }): Promise<void> {
    const {
      targetPath,
      pattern,
      sensitive = false,
      ignoredExtensions = [],
      onResultBatch,
      token,
    } = options;

    if (token?.isCancellationRequested) {
      return;
    }
    try {
      await this.runRipgrep({
        targetPath,
        pattern,
        sensitive,
        ignoredExtensions,
        usePcre2: true,
        onResultBatch,
        token,
      });
    } catch {
      if (token?.isCancellationRequested) {
        return;
      }
      logger.warn('PCRE2 failed, falling back to standard engine');
      try {
        await this.runRipgrep({
          targetPath,
          pattern,
          sensitive,
          ignoredExtensions,
          usePcre2: false,
          onResultBatch,
          token,
        });
      } catch (standardError) {
        logger.error('Both engines failed', standardError);
      }
    }
  }

  private async runRipgrep(options: {
    targetPath: string;
    pattern: string;
    sensitive: boolean;
    ignoredExtensions: string[];
    usePcre2: boolean;
    onResultBatch?: (batch: Omit<ScanResult, 'ruleId' | 'ruleName'>[]) => void;
    token?: vscode.CancellationToken;
  }): Promise<void> {
    const { targetPath, pattern, sensitive, ignoredExtensions, usePcre2, onResultBatch, token } =
      options;
    if (token?.isCancellationRequested) return;

    const TIMEOUT_MS = this.configService.getScanTimeout();
    const args = this.buildRipgrepArgs(pattern, sensitive, ignoredExtensions, usePcre2);
    args.push(targetPath);

    const workerPath = path.join(__dirname, 'ScanWorker.js');

    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const worker = new Worker(workerPath);
      this.activeWorkers.add(worker);

      const cleanup = () => {
        this.activeWorkers.delete(worker);
        cancellationListener?.dispose();
      };

      const cancellationListener = token?.onCancellationRequested(() => {
        if (!settled) {
          settled = true;
          cleanup();
          worker.postMessage({ type: 'cancel' });
          void worker.terminate();
          resolve();
        }
      });

      worker.on('message', (msg: WorkerOutbound) => {
        if (settled) return;
        if (msg.type === 'chunk') {
          if (onResultBatch && msg.results.length > 0) {
            try {
              onResultBatch(msg.results);
            } catch (error) {
              settled = true;
              cleanup();
              void worker.terminate();
              reject(
                error instanceof Error
                  ? error
                  : new Error(`Failed to process scan result batch: ${String(error)}`)
              );
              return;
            }
          }
          try {
            worker.postMessage({ type: 'ack' });
          } catch {}
          return;
        }

        settled = true;
        cleanup();
        void worker.terminate();
        if (msg.type === 'done') {
          resolve();
        } else {
          reject(new Error(msg.message));
        }
      });

      worker.on('error', (error) => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(new Error(`Scan worker error: ${error.message}`));
        }
      });

      worker.on('exit', (code) => {
        this.activeWorkers.delete(worker);
        if (!settled) {
          settled = true;
          cancellationListener?.dispose();
          resolve();
          logger.warn(`Scan worker exited unexpectedly with code ${code}`);
        }
      });

      const request: ScanWorkerRequest = {
        type: 'scan',
        rgPath: this.config.path,
        args,
        pattern,
        sensitive,
        contextWindow: CONFIG_DEFAULTS.VALIDATOR_CONTEXT_WINDOW,
        timeoutMs: TIMEOUT_MS,
        chunkSize: CONFIG_LIMITS.SCAN_WORKER_STREAM_CHUNK_SIZE,
      };
      worker.postMessage(request);
    });
  }

  private buildRipgrepArgs(
    pattern: string,
    sensitive: boolean,
    ignoredExtensions: string[],
    usePCRE2: boolean,
    maxResults?: number
  ): string[] {
    const maxFileSize = this.configService.getMaxFileSize();
    const effectiveMaxResults = maxResults ?? this.config.maxResults;
    const args = ['--json', '--line-number', '--column', '--text', '--hidden', '--no-ignore'];
    if (effectiveMaxResults > 0) {
      args.push('--max-count', effectiveMaxResults.toString());
    }
    if (maxFileSize > 0) {
      args.push('--max-filesize', `${maxFileSize}`);
    }
    args.push('--heading', '--encoding', 'auto');
    if (usePCRE2) {
      args.push('--pcre2');
    }
    if (!sensitive) {
      args.push('--ignore-case');
    }
    for (const ext of ignoredExtensions) {
      args.push('--glob', `!*${ext}`);
    }
    args.push('--', pattern);

    return args;
  }

  getCurrentConfig(): RipgrepConfig {
    return { ...this.config };
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.cancelActiveScans();
    this.disposables.forEach((d) => d.dispose());
    this.disposables = [];
  }
}
