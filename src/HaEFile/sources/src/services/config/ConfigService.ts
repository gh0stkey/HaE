import * as vscode from 'vscode';
import { CONFIG_NAMESPACE, CONFIG_KEYS, CONFIG_DEFAULTS } from '../../types';

export class ConfigService {
  private static instance: ConfigService | null = null;

  private disposed = false;

  private disposables: vscode.Disposable[] = [];

  private changeListeners: Set<() => void> = new Set();

  private constructor() {
    this.disposables.push(
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (e.affectsConfiguration(CONFIG_NAMESPACE)) {
          this.notifyListeners();
        }
      })
    );
  }

  static getInstance(): ConfigService {
    if (ConfigService.instance === null || ConfigService.instance.disposed) {
      ConfigService.instance = new ConfigService();
    }

    return ConfigService.instance;
  }

  private getConfig(): vscode.WorkspaceConfiguration {
    return vscode.workspace.getConfiguration(CONFIG_NAMESPACE);
  }

  onConfigChange(listener: () => void): vscode.Disposable {
    this.changeListeners.add(listener);

    return {
      dispose: () => {
        this.changeListeners.delete(listener);
      },
    };
  }

  private notifyListeners(): void {
    this.changeListeners.forEach((listener) => listener());
  }

  getRipgrepPath(): string {
    return this.getConfig().get<string>(CONFIG_KEYS.RIPGREP_PATH, CONFIG_DEFAULTS.RIPGREP_PATH);
  }

  async setRipgrepPath(path: string): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.RIPGREP_PATH,
      path,
      vscode.ConfigurationTarget.Global
    );
  }

  isDecorationEnabled(): boolean {
    return this.getConfig().get<boolean>(
      CONFIG_KEYS.ENABLE_DECORATION,
      CONFIG_DEFAULTS.ENABLE_DECORATION
    );
  }

  async setDecorationEnabled(enabled: boolean): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.ENABLE_DECORATION,
      enabled,
      vscode.ConfigurationTarget.Global
    );
  }

  getDecorationDelay(): number {
    return this.getConfig().get<number>(
      CONFIG_KEYS.DECORATION_DELAY,
      CONFIG_DEFAULTS.DECORATION_DELAY
    );
  }

  async setDecorationDelay(delay: number): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.DECORATION_DELAY,
      delay,
      vscode.ConfigurationTarget.Global
    );
  }

  getMaxFileSize(): number {
    return this.getConfig().get<number>(CONFIG_KEYS.MAX_FILE_SIZE, CONFIG_DEFAULTS.MAX_FILE_SIZE);
  }

  async setMaxFileSize(size: number): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.MAX_FILE_SIZE,
      size,
      vscode.ConfigurationTarget.Global
    );
  }

  getIgnoredExtensions(): string[] {
    const fallbackExtensions = [...CONFIG_DEFAULTS.IGNORED_EXTENSIONS];
    const extensions = this.getConfig().get<string[]>(
      CONFIG_KEYS.IGNORED_EXTENSIONS,
      fallbackExtensions
    );

    return Array.isArray(extensions) ? [...extensions] : fallbackExtensions;
  }

  isExtensionIgnored(filePath: string): boolean {
    const ext = filePath.startsWith('.')
      ? filePath.toLowerCase()
      : filePath.includes('.')
        ? '.' + filePath.split('.').pop()?.toLowerCase()
        : '';
    if (!ext) return false;
    const ignoredExtensions = this.getIgnoredExtensions();
    return ignoredExtensions.some((ignored) => ignored.toLowerCase() === ext);
  }

  async setIgnoredExtensions(extensions: string[]): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.IGNORED_EXTENSIONS,
      extensions,
      vscode.ConfigurationTarget.Global
    );
  }

  getMaxResults(): number {
    return this.getConfig().get<number>(CONFIG_KEYS.MAX_RESULTS, CONFIG_DEFAULTS.MAX_RESULTS);
  }

  async setMaxResults(maxResults: number): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.MAX_RESULTS,
      maxResults,
      vscode.ConfigurationTarget.Global
    );
  }

  getScanTimeout(): number {
    return this.getConfig().get<number>(CONFIG_KEYS.SCAN_TIMEOUT, CONFIG_DEFAULTS.SCAN_TIMEOUT);
  }

  async setScanTimeout(timeout: number): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.SCAN_TIMEOUT,
      timeout,
      vscode.ConfigurationTarget.Global
    );
  }

  getScanWorkerMaxConcurrency(): number {
    return this.getConfig().get<number>(
      CONFIG_KEYS.SCAN_WORKER_MAX_CONCURRENCY,
      CONFIG_DEFAULTS.SCAN_WORKER_MAX_CONCURRENCY
    );
  }

  async setScanWorkerMaxConcurrency(value: number): Promise<void> {
    await this.getConfig().update(
      CONFIG_KEYS.SCAN_WORKER_MAX_CONCURRENCY,
      value,
      vscode.ConfigurationTarget.Global
    );
  }

  getRawRules(): unknown[] {
    return this.getConfig().get<unknown[]>(CONFIG_KEYS.RULES, []);
  }

  async setRules(rules: unknown[]): Promise<void> {
    await this.getConfig().update(CONFIG_KEYS.RULES, rules, vscode.ConfigurationTarget.Global);
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.disposables.forEach((d) => d.dispose());
    this.disposables = [];
    this.changeListeners.clear();
  }
}
