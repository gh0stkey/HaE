import { parentPort } from 'worker_threads';
import { spawn, ChildProcess } from 'child_process';
import * as readline from 'readline';

interface RawScanResult {
  file: string;
  line: number;
  column: number;
  match: string;
  context: { before: string; after: string };
}

type RipgrepTextField = { text: string } | { bytes: string } | string;

interface RipgrepSubmatch {
  match: RipgrepTextField;
  start: number;
  end: number;
}

interface RipgrepMatchData {
  path: RipgrepTextField;
  lines: RipgrepTextField;
  line_number: number;
  absolute_offset: number;
  submatches: RipgrepSubmatch[];
}

export interface ScanWorkerRequest {
  type: 'scan';
  rgPath: string;
  args: string[];
  pattern: string;
  sensitive: boolean;
  contextWindow: number;
  timeoutMs: number;
  chunkSize: number;
}

interface CancelWorkerRequest {
  type: 'cancel';
}

interface AckWorkerRequest {
  type: 'ack';
}

type WorkerInbound = ScanWorkerRequest | CancelWorkerRequest | AckWorkerRequest;

interface WorkerDoneMessage {
  type: 'done';
}

interface WorkerChunkMessage {
  type: 'chunk';
  results: RawScanResult[];
}

interface WorkerErrorMessage {
  type: 'error';
  message: string;
}

export type WorkerOutbound = WorkerDoneMessage | WorkerChunkMessage | WorkerErrorMessage;

function extractText(field: RipgrepTextField): string {
  if (typeof field === 'string') return field;
  if ('text' in field && typeof field.text === 'string') return field.text;
  if ('bytes' in field && typeof field.bytes === 'string') {
    try {
      return Buffer.from(field.bytes, 'base64').toString('utf8');
    } catch {
      return '';
    }
  }
  return '';
}

function isMatch(obj: unknown): obj is { type: 'match'; data: RipgrepMatchData } {
  if (!obj || typeof obj !== 'object') return false;
  const msg = obj as Record<string, unknown>;
  if (msg.type !== 'match') return false;
  const data = msg.data;
  if (!data || typeof data !== 'object') return false;
  const d = data as Record<string, unknown>;
  if (d.path === undefined) return false;
  if (typeof d.line_number !== 'number' || d.line_number < 1) return false;
  if (!Array.isArray(d.submatches)) return false;
  return true;
}

function isSubmatch(obj: unknown): obj is RipgrepSubmatch {
  if (!obj || typeof obj !== 'object') return false;
  const s = obj as Record<string, unknown>;
  if (typeof s.start !== 'number') return false;
  if (s.match === undefined) return false;
  if (
    typeof s.match !== 'string' &&
    (typeof s.match !== 'object' ||
      s.match === null ||
      (typeof (s.match as Record<string, unknown>).text !== 'string' &&
        typeof (s.match as Record<string, unknown>).bytes !== 'string'))
  ) {
    return false;
  }
  return true;
}

function byteToChar(text: string, byteOffset: number): number {
  const buf = Buffer.from(text, 'utf8');
  if (byteOffset <= 0) return 0;
  if (byteOffset >= buf.length) return text.length;
  let aligned = byteOffset;
  while (aligned > 0 && (buf[aligned] & 0xc0) === 0x80) aligned--;
  return buf.subarray(0, aligned).toString('utf8').length;
}

function buildCaptureRegex(pattern: string, sensitive: boolean): RegExp | null {
  try {
    return new RegExp(pattern, sensitive ? '' : 'i');
  } catch {
    return null;
  }
}

function captureGroup(
  fullMatch: string,
  captureRegex: RegExp | null
): { extracted: string; offset: number } {
  if (captureRegex) {
    const m = captureRegex.exec(fullMatch);
    if (m && m[1] !== undefined) {
      const idx = Math.max(0, fullMatch.indexOf(m[1]));
      return { extracted: m[1], offset: Buffer.from(fullMatch.slice(0, idx), 'utf8').length };
    }
  }
  return { extracted: fullMatch, offset: 0 };
}

function parseLine(
  line: string,
  ctxWindow: number,
  out: RawScanResult[],
  captureRegex: RegExp | null
): void {
  let data: unknown;
  try {
    data = JSON.parse(line);
  } catch {
    return;
  }
  if (!isMatch(data)) return;

  const md = data.data;
  const filePath = extractText(md.path);
  const lineText = extractText(md.lines);
  for (const sub of md.submatches) {
    if (!isSubmatch(sub)) continue;
    const full = extractText(sub.match);
    const { extracted, offset } = captureGroup(full, captureRegex);
    const col = byteToChar(lineText, sub.start + offset);
    const end = Math.min(lineText.length, col + extracted.length);
    out.push({
      file: filePath,
      line: md.line_number,
      column: col,
      match: extracted,
      context: {
        before: lineText.slice(Math.max(0, col - ctxWindow), col),
        after: lineText.slice(end, Math.min(lineText.length, end + ctxWindow)),
      },
    });
  }
}

let activeChild: ChildProcess | null = null;
let cancelled = false;
let onChunkAck: (() => void) | null = null;

parentPort!.on('message', (msg: WorkerInbound) => {
  if (msg.type === 'cancel') {
    cancelled = true;
    if (activeChild) {
      try {
        activeChild.kill('SIGKILL');
      } catch {}
    }
    return;
  }
  if (msg.type === 'ack') {
    onChunkAck?.();
    return;
  }
  if (msg.type === 'scan') {
    cancelled = false;
    runScan(msg);
  }
});

function runScan(req: ScanWorkerRequest): void {
  const results: RawScanResult[] = [];
  const { rgPath, args, pattern, sensitive, contextWindow, timeoutMs, chunkSize } = req;
  const captureRegex = buildCaptureRegex(pattern, sensitive);
  const effectiveChunkSize = chunkSize > 0 ? chunkSize : 500;
  let awaitingChunkAck = false;

  const pauseOutput = () => {
    activeChild?.stdout?.pause();
  };

  const resumeOutput = () => {
    activeChild?.stdout?.resume();
  };

  const flushResults = (waitForAck: boolean) => {
    if (results.length === 0) {
      return;
    }
    parentPort!.postMessage({
      type: 'chunk',
      results: results.splice(0, results.length),
    } satisfies WorkerOutbound);
    if (waitForAck) {
      awaitingChunkAck = true;
      pauseOutput();
    }
  };

  try {
    const child = spawn(rgPath, args);
    activeChild = child;
    let stderr = '';
    let timedOut = false;

    let timeout: ReturnType<typeof setTimeout> | undefined;
    if (timeoutMs > 0) {
      timeout = setTimeout(() => {
        timedOut = true;
        try {
          child.kill('SIGKILL');
        } catch {}
      }, timeoutMs);
    }

    if (child.stdout) {
      const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
      onChunkAck = () => {
        if (!awaitingChunkAck) {
          return;
        }
        awaitingChunkAck = false;
        if (!cancelled && !timedOut) {
          resumeOutput();
        }
      };

      rl.on('line', (line) => {
        if (cancelled || timedOut) return;
        if (line.trim()) {
          parseLine(line, contextWindow, results, captureRegex);
          if (!awaitingChunkAck && results.length >= effectiveChunkSize) {
            flushResults(true);
          }
        }
      });
    }

    child.stderr?.on('data', (data: Buffer) => {
      if (stderr.length < 10240) stderr += data.toString();
    });

    child.on('error', (error) => {
      if (timeout) clearTimeout(timeout);
      onChunkAck = null;
      activeChild = null;
      if (!cancelled) {
        parentPort!.postMessage({
          type: 'error',
          message: `Failed to spawn ripgrep: ${error.message}`,
        } satisfies WorkerOutbound);
      }
    });

    child.on('exit', (_code) => {
      if (timeout) clearTimeout(timeout);
      onChunkAck = null;
      activeChild = null;

      if (cancelled) {
        parentPort!.postMessage({ type: 'done' } satisfies WorkerOutbound);
        return;
      }

      if (timedOut) {
        parentPort!.postMessage({
          type: 'error',
          message: `Ripgrep timed out after ${timeoutMs / 1000}s`,
        } satisfies WorkerOutbound);
        return;
      }

      if (stderr && (stderr.includes('PCRE2') || stderr.includes('error compiling pattern'))) {
        parentPort!.postMessage({ type: 'error', message: stderr } satisfies WorkerOutbound);
        return;
      }

      flushResults(false);
      parentPort!.postMessage({ type: 'done' } satisfies WorkerOutbound);
    });
  } catch (error) {
    onChunkAck = null;
    parentPort!.postMessage({
      type: 'error',
      message: `Ripgrep execution failed: ${error instanceof Error ? error.message : String(error)}`,
    } satisfies WorkerOutbound);
  }
}
