import * as vscode from 'vscode';
import { ScanResult } from '../../types';
import { Logger } from '../../utils/logger';

interface PersistedScanResultsFile {
  paths: string[];
  displayName: string;
  results: Record<string, ScanResult[]>;
  timestamp: number;
  duration?: number;
}

export interface RestoredScanResults {
  paths: string[];
  displayName: string;
  results: Map<string, ScanResult[]>;
  duration?: number;
  totalResults: number;
}

export class ScanResultsStorage {
  constructor(private readonly context: vscode.ExtensionContext) {}

  async save(
    paths: string[],
    displayName: string,
    results: Map<string, ScanResult[]>,
    duration?: number
  ): Promise<void> {
    try {
      const resultsUri = this.getResultsUri();
      if (!resultsUri) {
        Logger.warn('No storage URI available, cannot save scan results');
        return;
      }

      const data: PersistedScanResultsFile = {
        paths,
        displayName,
        results: Object.fromEntries(results),
        timestamp: Date.now(),
        duration,
      };

      const storageDir = vscode.Uri.joinPath(resultsUri, '..');
      try {
        await vscode.workspace.fs.stat(storageDir);
      } catch {
        await vscode.workspace.fs.createDirectory(storageDir);
      }

      const content = Buffer.from(JSON.stringify(data), 'utf8');
      await vscode.workspace.fs.writeFile(resultsUri, content);
    } catch (error) {
      Logger.error('Failed to save scan results', error);
    }
  }

  async restore(): Promise<RestoredScanResults | undefined> {
    try {
      const resultsUri = this.getResultsUri();
      if (!resultsUri) {
        return undefined;
      }

      let savedData: PersistedScanResultsFile | undefined;
      try {
        const content = await vscode.workspace.fs.readFile(resultsUri);
        savedData = JSON.parse(Buffer.from(content).toString('utf8')) as PersistedScanResultsFile;
      } catch {
        return undefined;
      }

      if (!savedData) {
        return undefined;
      }

      if (
        !Array.isArray(savedData.paths) ||
        typeof savedData.results !== 'object' ||
        savedData.results === null
      ) {
        Logger.warn('Invalid scan results structure in storage, clearing');
        await this.clear();
        return undefined;
      }

      const results = new Map(Object.entries(savedData.results));
      let totalResults = 0;
      for (const groupResults of results.values()) {
        totalResults += groupResults.length;
      }

      return {
        paths: savedData.paths,
        displayName: savedData.displayName,
        results,
        duration: savedData.duration,
        totalResults,
      };
    } catch (error) {
      Logger.error('Failed to restore scan results', error);
      await this.clear();
      return undefined;
    }
  }

  async clear(): Promise<void> {
    const resultsUri = this.getResultsUri();
    if (!resultsUri) {
      return;
    }

    try {
      await vscode.workspace.fs.delete(resultsUri);
    } catch {}
  }

  private getResultsUri(): vscode.Uri | undefined {
    const storageUri = this.context.storageUri;
    if (!storageUri) {
      return undefined;
    }

    return vscode.Uri.joinPath(storageUri, 'lastScanResults.json');
  }
}
