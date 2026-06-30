import * as vscode from 'vscode';
import { spawn } from 'child_process';
import {
  ScanRule,
  ScanResult,
  ValidatorInput,
  ValidatorInputItem,
  ValidatorOutput,
  Severity,
} from '../../types';
import { CONFIG_DEFAULTS } from '../../types';
import { createScopedLogger } from '../../utils/logger';
import { isValidValidatorOutput, SEVERITY } from '../../utils/validation';

const logger = createScopedLogger('ValidatorService');
const DEFAULT_TIMEOUT = 5000;
const DEFAULT_BULK = CONFIG_DEFAULTS.VALIDATOR_BULK_DEFAULT;

export class ValidatorService {
  private static instance: ValidatorService | null = null;

  private disposed = false;

  private contextCache = new Map<string, { before: string; after: string }>();

  private constructor() {}

  static getInstance(): ValidatorService {
    if (ValidatorService.instance === null || ValidatorService.instance.disposed) {
      ValidatorService.instance = new ValidatorService();
    }

    return ValidatorService.instance;
  }

  async validateAsyncDeduped(
    rule: ScanRule,
    matches: ScanResult[],
    token?: vscode.CancellationToken,
    onMatch?: (result: ScanResult) => void | Promise<void>
  ): Promise<void> {
    if (this.disposed) {
      logger.warn('ValidatorService is disposed');
      return;
    }

    if (!rule.validator?.command) {
      await this.applyDefaultSeverity(matches, token, onMatch);
      return;
    }

    const matchGroups = this.groupMatchesByValue(matches);
    const timeout = rule.validator.timeout ?? DEFAULT_TIMEOUT;
    const bulk = rule.validator.bulk ?? DEFAULT_BULK;
    const uniqueMatches = Array.from(matchGroups.keys());

    for (let i = 0; i < uniqueMatches.length; i += bulk) {
      if (token?.isCancellationRequested) return;

      const batch = uniqueMatches.slice(i, i + bulk);
      const severityResults = await this.validateBulkMatches(
        batch,
        matchGroups,
        rule,
        timeout,
        token
      );

      if (token?.isCancellationRequested) return;

      await this.applyBatchResults(severityResults, matchGroups, token, onMatch);
    }
  }

  private async applyDefaultSeverity(
    matches: ScanResult[],
    token?: vscode.CancellationToken,
    onMatch?: (result: ScanResult) => void | Promise<void>
  ): Promise<void> {
    let processed = 0;
    for (const m of matches) {
      if (token?.isCancellationRequested) return;
      m.severity = SEVERITY.NONE;
      await onMatch?.(m);
      processed++;
      if ((processed & 255) === 0) {
        await new Promise<void>((resolve) => setImmediate(resolve));
      }
    }
  }

  private groupMatchesByValue(matches: ScanResult[]): Map<string, ScanResult[]> {
    const matchGroups = new Map<string, ScanResult[]>();
    for (const match of matches) {
      const key = match.match;
      if (!matchGroups.has(key)) {
        matchGroups.set(key, []);
      }
      matchGroups.get(key)!.push(match);
    }
    return matchGroups;
  }

  private async validateBulkMatches(
    batch: string[],
    matchGroups: Map<string, ScanResult[]>,
    rule: ScanRule,
    timeout: number,
    token?: vscode.CancellationToken
  ): Promise<{ matchValue: string; severity: Severity }[]> {
    const items: ValidatorInputItem[] = [];
    for (let i = 0; i < batch.length; i++) {
      if (token?.isCancellationRequested) {
        return [];
      }
      const representative = matchGroups.get(batch[i])![0];
      const context = await this.getMatchContext(representative);
      items.push({
        index: i,
        data: {
          file: representative.file,
          line: representative.line,
          column: representative.column,
          match: representative.match,
          context,
        },
      });
    }

    const input: ValidatorInput = {
      rule: {
        id: rule.id,
        name: rule.name,
        regex: rule.regex,
        group: rule.group,
      },
      items,
    };

    const output = await this.executeValidator(rule.validator!.command, input, timeout, token);
    const severityMap = new Map<number, Severity>();
    if (output) {
      for (const result of output.results) {
        severityMap.set(result.index, result.tags);
      }
      if (severityMap.size < batch.length) {
        logger.warn(
          `Validator returned ${severityMap.size}/${batch.length} results, missing indices default to 'none'`
        );
      }
    }

    return batch.map((matchValue, i) => ({
      matchValue,
      severity: severityMap.get(i) ?? SEVERITY.NONE,
    }));
  }

  private async applyBatchResults(
    severityResults: { matchValue: string; severity: Severity }[],
    matchGroups: Map<string, ScanResult[]>,
    token?: vscode.CancellationToken,
    onMatch?: (result: ScanResult) => void | Promise<void>
  ): Promise<void> {
    let processed = 0;
    for (const { matchValue, severity } of severityResults) {
      if (token?.isCancellationRequested) {
        return;
      }
      const group = matchGroups.get(matchValue);
      if (!group) {
        continue;
      }
      for (const match of group) {
        if (token?.isCancellationRequested) {
          return;
        }
        match.severity = severity;
        await onMatch?.(match);
        processed++;
        if ((processed & 255) === 0) {
          await new Promise<void>((resolve) => setImmediate(resolve));
        }
      }
    }
  }

  private async getMatchContext(match: ScanResult): Promise<{ before: string; after: string }> {
    if (match.context) {
      return match.context;
    }

    const cacheKey = `${match.file}:${match.line}:${match.column}:${match.match}`;
    const cached = this.contextCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const emptyContext = { before: '', after: '' };
    this.contextCache.set(cacheKey, emptyContext);

    return emptyContext;
  }

  private async executeValidator(
    command: string,
    input: ValidatorInput,
    timeout: number,
    token?: vscode.CancellationToken
  ): Promise<ValidatorOutput | null> {
    try {
      const inputJson = JSON.stringify(input);
      const output = await this.runCommandWithStdin(command, inputJson, timeout, token);
      if (!output) {
        return null;
      }
      const parsed = JSON.parse(output);
      if (!isValidValidatorOutput(parsed)) {
        logger.warn(`Invalid validator output structure: ${output}`);

        return null;
      }

      return parsed;
    } catch (error) {
      logger.error('Validator execution failed', error);

      return null;
    }
  }

  private runCommandWithStdin(
    command: string,
    input: string,
    timeout: number,
    token?: vscode.CancellationToken
  ): Promise<string | null> {
    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let isResolved = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let forceKillTimer: ReturnType<typeof setTimeout> | undefined;
      const shell = process.platform === 'win32' ? 'cmd' : '/bin/sh';
      const shellArg = process.platform === 'win32' ? '/c' : '-c';
      const child = spawn(shell, [shellArg, command], {
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: process.platform === 'win32',
      });

      const requestTerminate = () => {
        try {
          child.kill('SIGTERM');
        } catch {}
        forceKillTimer = setTimeout(() => {
          if (child.exitCode !== null || child.signalCode !== null) {
            return;
          }
          try {
            child.kill('SIGKILL');
          } catch {}
        }, 700);
      };

      const cancellationListener = token?.onCancellationRequested(() => {
        requestTerminate();
        finish(null);
      });

      const cleanup = () => {
        if (timer) {
          clearTimeout(timer);
        }
        if (forceKillTimer) {
          clearTimeout(forceKillTimer);
        }
        cancellationListener?.dispose();
      };

      const finish = (value: string | null) => {
        if (isResolved) {
          return;
        }
        isResolved = true;
        cleanup();
        resolve(value);
      };

      if (token?.isCancellationRequested) {
        requestTerminate();
        finish(null);
        return;
      }

      if (timeout > 0) {
        timer = setTimeout(() => {
          timedOut = true;
          requestTerminate();
          logger.warn(`Validator timed out after ${timeout}ms`);
          finish(null);
        }, timeout);
      }

      if (child.stdin) {
        child.stdin.on('error', (error) => {
          if (!isResolved) {
            logger.debug('Validator stdin error', error);
          }
        });
        try {
          child.stdin.write(input);
          child.stdin.end();
        } catch (error) {
          logger.debug('Failed writing validator stdin', error);
          finish(null);
          return;
        }
      }
      child.stdout?.on('data', (data) => {
        stdout += data.toString();
      });
      child.stderr?.on('data', (data) => {
        stderr += data.toString();
      });
      child.on('error', (error) => {
        logger.error('Failed to spawn validator', error);
        finish(null);
      });
      child.on('close', (code) => {
        if (timedOut) {
          finish(null);

          return;
        }
        if (code !== 0) {
          logger.warn(`Validator exited with code ${code}: ${stderr}`);
          finish(null);

          return;
        }
        finish(stdout.trim());
      });
    });
  }

  dispose(): void {
    this.disposed = true;
    this.contextCache.clear();
  }
}
