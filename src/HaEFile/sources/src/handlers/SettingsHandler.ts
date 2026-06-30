import { ConfigService, DecorationService, ScanService } from '../services';
import { createScopedNotifier } from '../utils/logger';

const notify = createScopedNotifier('Settings');

export class SettingsHandler {
  private configService: ConfigService;

  constructor() {
    this.configService = ConfigService.getInstance();
  }

  isDecorationEnabled(): boolean {
    return DecorationService.getInstance().isEnabled();
  }

  async toggleDecoration(enabled: boolean): Promise<void> {
    DecorationService.getInstance().setEnabled(enabled);
    const status = enabled ? 'enabled' : 'disabled';
    notify.success('Toggle decoration', `Real-time highlighting ${status}`);
  }

  getDecorationDelay(): number {
    return this.configService.getDecorationDelay();
  }

  async setDecorationDelay(delay: number): Promise<void> {
    await this.configService.setDecorationDelay(delay);
    notify.success('Update decoration delay', `${delay}ms`);
  }

  getMaxFileSize(): number {
    return this.configService.getMaxFileSize();
  }

  async setMaxFileSize(size: number): Promise<void> {
    await this.configService.setMaxFileSize(size);
    const detail = size === 0 ? 'No limit' : `${(size / 1024 / 1024).toFixed(1)}MB`;
    notify.success('Update max file size', detail);
  }

  getIgnoredExtensions(): string[] {
    return this.configService.getIgnoredExtensions();
  }

  async setIgnoredExtensions(extensions: string[]): Promise<void> {
    await this.configService.setIgnoredExtensions(extensions);
    const details = extensions.length > 0 ? extensions.join(', ') : '(none)';
    notify.success('Update ignored extensions', details);
  }

  getMaxResults(): number {
    return this.configService.getMaxResults();
  }

  async setMaxResults(value: number): Promise<void> {
    await this.configService.setMaxResults(value);
    notify.success('Update max results', value === 0 ? 'No limit' : `${value}`);
  }

  getScanTimeout(): number {
    return this.configService.getScanTimeout();
  }

  async setScanTimeout(value: number): Promise<void> {
    await this.configService.setScanTimeout(value);
    const detail = value === 0 ? 'No limit' : `${(value / 1000).toFixed(1)}s`;
    notify.success('Update scan timeout', detail);
  }

  getScanWorkerMaxConcurrency(): number {
    return this.configService.getScanWorkerMaxConcurrency();
  }

  async setScanWorkerMaxConcurrency(value: number): Promise<void> {
    await this.configService.setScanWorkerMaxConcurrency(value);
    notify.success('Update scan worker max concurrency', `${value}`);
  }

  getRipgrepPath(): string {
    return ScanService.getInstance().getCurrentConfig().path;
  }

  async validateRipgrepPath(path: string): Promise<boolean> {
    return ScanService.getInstance().testRipgrepPathWithCustomPath(path);
  }

  async setRipgrepPath(path: string): Promise<boolean> {
    const success = await ScanService.getInstance().setRipgrepPath(path);
    if (success) {
      notify.success('Update ripgrep path', path);
    }

    return success;
  }
}
