import * as vscode from 'vscode';
import { createScopedLogger } from '../../utils/logger';

const logger = createScopedLogger('JobController');

export type JobKind = 'scan' | 'revalidate';

const JOB_PRIORITY: Record<JobKind, number> = {
  scan: 100,
  revalidate: 50,
};

interface ActiveJob {
  id: string;
  kind: JobKind;
  priority: number;
  label?: string;
  cts: vscode.CancellationTokenSource;
}

export interface JobTicket {
  id: string;
  kind: JobKind;
  token: vscode.CancellationToken;
  cancel: () => void;
  complete: () => void;
}

export class JobController {
  private static instance: JobController | null = null;

  private disposed = false;

  private seq = 0;

  private jobs = new Map<string, ActiveJob>();

  private constructor() {}

  static getInstance(): JobController {
    if (JobController.instance === null || JobController.instance.disposed) {
      JobController.instance = new JobController();
    }

    return JobController.instance;
  }

  startJob(
    kind: JobKind,
    options?: {
      label?: string;
      preemptLowerPriority?: boolean;
      replaceSameKind?: boolean;
    }
  ): JobTicket | null {
    if (this.disposed) {
      logger.warn(`Cannot start ${kind} job after disposal`);
      return null;
    }

    const { label, preemptLowerPriority = false, replaceSameKind = false } = options || {};
    const priority = JOB_PRIORITY[kind];

    if (replaceSameKind) {
      this.cancelKind(kind, 'replaced-by-new-job');
    } else if (this.hasActiveKind(kind)) {
      logger.info(`Skip ${kind} job: same kind already active`);
      return null;
    }

    if (this.hasActiveHigherPriority(priority)) {
      logger.info(`Skip ${kind} job: higher-priority job is active`);
      return null;
    }

    if (preemptLowerPriority) {
      this.cancelLowerPriority(priority, `${kind}-preempt`);
    }

    const id = `${kind}-${++this.seq}`;
    const cts = new vscode.CancellationTokenSource();
    const job: ActiveJob = {
      id,
      kind,
      priority,
      label,
      cts,
    };

    this.jobs.set(id, job);
    logger.info(`Started job ${id}${label ? ` (${label})` : ''}`);

    return {
      id,
      kind,
      token: cts.token,
      cancel: () => this.cancelJob(id, 'ticket-cancel'),
      complete: () => this.completeJob(id),
    };
  }

  hasActiveJobs(): boolean {
    return this.jobs.size > 0;
  }

  hasActiveKind(kind: JobKind): boolean {
    for (const job of this.jobs.values()) {
      if (job.kind === kind) {
        return true;
      }
    }
    return false;
  }

  cancelKind(kind: JobKind, reason = 'cancel-kind'): void {
    for (const job of this.jobs.values()) {
      if (job.kind === kind) {
        this.cancelJob(job.id, reason);
      }
    }
  }

  cancelAll(reason = 'cancel-all'): void {
    for (const job of this.jobs.values()) {
      this.cancelJob(job.id, reason);
    }
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.cancelAll('dispose');
    for (const [id, job] of this.jobs) {
      job.cts.dispose();
      this.jobs.delete(id);
    }
  }

  private cancelJob(id: string, reason: string): void {
    const job = this.jobs.get(id);
    if (!job || job.cts.token.isCancellationRequested) {
      return;
    }
    logger.info(`Cancelling job ${id}: ${reason}`);
    job.cts.cancel();
  }

  private completeJob(id: string): void {
    const job = this.jobs.get(id);
    if (!job) {
      return;
    }
    logger.info(`Completed job ${id}`);
    job.cts.dispose();
    this.jobs.delete(id);
  }

  private hasActiveHigherPriority(priority: number): boolean {
    for (const job of this.jobs.values()) {
      if (job.priority > priority) {
        return true;
      }
    }
    return false;
  }

  private cancelLowerPriority(priority: number, reason: string): void {
    for (const job of this.jobs.values()) {
      if (job.priority < priority) {
        this.cancelJob(job.id, reason);
      }
    }
  }
}
