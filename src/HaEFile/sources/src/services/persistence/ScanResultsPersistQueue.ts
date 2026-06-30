import * as vscode from 'vscode';
import { ScanResult } from '../../types';
import { createScopedLogger } from '../../utils/logger';

const logger = createScopedLogger('ScanResultsPersistQueue');

interface PersistMetadata {
  paths: string[];
  displayName: string;
  duration?: number;
}

interface PersistTask {
  results: Map<string, ScanResult[]>;
  duration?: number;
}

export interface PersistWriteRequest extends PersistMetadata {
  results: Map<string, ScanResult[]>;
}

export class ScanResultsPersistQueue implements vscode.Disposable {
  private disposed = false;

  private writing = false;

  private metadata?: PersistMetadata;

  private pending?: PersistTask;

  private timer?: ReturnType<typeof setTimeout>;

  private inFlight?: Promise<void>;

  constructor(
    private readonly writer: (request: PersistWriteRequest) => Promise<void>,
    private readonly debounceMs: number
  ) {}

  setMetadata(paths: string[], displayName: string, duration?: number): void {
    this.metadata = {
      paths: [...paths],
      displayName,
      duration,
    };
  }

  enqueue(results: Map<string, ScanResult[]>, duration?: number): void {
    if (this.disposed || !this.metadata) {
      return;
    }
    if (duration !== undefined) {
      this.metadata.duration = duration;
    }
    this.pending = { results, duration };
    this.schedule();
  }

  async flushNow(results: Map<string, ScanResult[]>, duration?: number): Promise<void> {
    if (this.disposed || !this.metadata) {
      return;
    }
    if (duration !== undefined) {
      this.metadata.duration = duration;
    }
    this.pending = { results, duration };
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }

    while (!this.disposed && (this.writing || this.pending)) {
      if (this.writing) {
        if (this.inFlight) {
          await this.inFlight;
        }
        continue;
      }
      await this.flush();
      if (this.inFlight) {
        await this.inFlight;
      }
    }
  }

  clear(): void {
    this.pending = undefined;
    this.metadata = undefined;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }

  private schedule(): void {
    if (this.timer || this.disposed) {
      return;
    }
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.flush();
    }, this.debounceMs);
  }

  private async flush(): Promise<void> {
    if (this.disposed || this.writing || !this.pending || !this.metadata) {
      return;
    }

    const task = this.pending;
    this.pending = undefined;

    const metadata: PersistMetadata = {
      paths: [...this.metadata.paths],
      displayName: this.metadata.displayName,
      duration: this.metadata.duration,
    };

    const duration = task.duration ?? metadata.duration;

    this.writing = true;
    const writeTask = (async () => {
      try {
        await this.writer({
          paths: metadata.paths,
          displayName: metadata.displayName,
          results: task.results,
          duration,
        });
        if (duration !== undefined && this.metadata) {
          this.metadata.duration = duration;
        }
      } catch (error) {
        logger.error('Failed to persist scan results from queue', error);
      } finally {
        this.writing = false;
        this.inFlight = undefined;
        if (this.pending && !this.timer && !this.disposed) {
          this.schedule();
        }
      }
    })();

    this.inFlight = writeTask;
    await writeTask;
  }
}
