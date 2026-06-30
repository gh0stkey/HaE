import * as vscode from 'vscode';

enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

interface LoggerConfig {
  minLevel: LogLevel;
  prefix: string;
  showUserNotifications: boolean;
}
interface NotificationMessage {
  module: string;
  action: string;
  details?: string;
}

function formatNotification(msg: NotificationMessage | string): string {
  if (typeof msg === 'string') {
    return msg;
  }
  const parts = [`[${msg.module}]`, msg.action];
  if (msg.details) {
    parts.push(`- ${msg.details}`);
  }

  return parts.join(' ');
}

export class Logger {
  private static config: LoggerConfig = {
    minLevel: LogLevel.INFO,
    prefix: '[HaE]',
    showUserNotifications: true,
  };

  private static outputChannel: vscode.OutputChannel | null = null;

  static initialize(outputChannel?: vscode.OutputChannel): void {
    Logger.outputChannel = outputChannel || vscode.window.createOutputChannel('HaE');
  }

  static debug(message: string, ...args: unknown[]): void {
    if (Logger.config.minLevel <= LogLevel.DEBUG) {
      const fullMessage = Logger.formatMessage('DEBUG', message);
      Logger.outputChannel?.appendLine(fullMessage + Logger.formatArgs(args));
    }
  }

  static info(message: string, ...args: unknown[]): void {
    if (Logger.config.minLevel <= LogLevel.INFO) {
      const fullMessage = Logger.formatMessage('INFO', message);
      Logger.outputChannel?.appendLine(fullMessage + Logger.formatArgs(args));
    }
  }

  static warn(message: string, ...args: unknown[]): void {
    if (Logger.config.minLevel <= LogLevel.WARN) {
      const fullMessage = Logger.formatMessage('WARN', message);
      console.warn(fullMessage, ...args);
      Logger.outputChannel?.appendLine(fullMessage + Logger.formatArgs(args));
    }
  }

  static error(message: string, error?: unknown): void {
    if (Logger.config.minLevel <= LogLevel.ERROR) {
      const fullMessage = Logger.formatMessage('ERROR', message);
      console.error(fullMessage, error);
      const errorDetails = error instanceof Error ? error.message : String(error);
      Logger.outputChannel?.appendLine(fullMessage);
      if (error) {
        Logger.outputChannel?.appendLine(`  Error: ${errorDetails}`);
        if (error instanceof Error && error.stack) {
          Logger.outputChannel?.appendLine(`  Stack: ${error.stack}`);
        }
      }
    }
  }

  static dispose(): void {
    Logger.outputChannel?.dispose();
    Logger.outputChannel = null;
  }

  private static formatMessage(level: string, message: string): string {
    const timestamp = new Date().toISOString().substring(11, 23);

    return `${Logger.config.prefix} [${timestamp}] [${level}] ${message}`;
  }

  private static formatArgs(args: unknown[]): string {
    if (args.length === 0) {
      return '';
    }
    try {
      const formatted = args.map((arg) => {
        if (arg instanceof Error) {
          return arg.message;
        }
        if (typeof arg === 'object') {
          return JSON.stringify(arg, null, 2);
        }

        return String(arg);
      });

      return '\n  ' + formatted.join('\n  ');
    } catch {
      return ' [Unable to format arguments]';
    }
  }
}

export class Notifier {
  static info(msg: NotificationMessage | string): void {
    const message = formatNotification(msg);
    Logger.info(message);
    vscode.window.showInformationMessage(`HaE: ${message}`);
  }

  static warning(msg: NotificationMessage | string): void {
    const message = formatNotification(msg);
    Logger.warn(message);
    vscode.window.showWarningMessage(`HaE: ${message}`);
  }

  static error(msg: NotificationMessage | string, error?: unknown): void {
    const message = formatNotification(msg);
    const errorDetails = error instanceof Error ? error.message : error ? String(error) : '';
    const fullMessage = errorDetails ? `${message}: ${errorDetails}` : message;
    Logger.error(message, error);
    vscode.window.showErrorMessage(`HaE: ${fullMessage}`);
  }

  static async confirm(
    msg: NotificationMessage | string,
    ...actions: string[]
  ): Promise<string | undefined> {
    const message = formatNotification(msg);
    Logger.warn(message);

    return vscode.window.showWarningMessage(`HaE: ${message}`, ...actions);
  }
}

export function createScopedLogger(scope: string) {
  return {
    debug: (message: string, ...args: unknown[]) => Logger.debug(`[${scope}] ${message}`, ...args),
    info: (message: string) => Logger.info(`[${scope}] ${message}`),
    warn: (message: string) => Logger.warn(`[${scope}] ${message}`),
    error: (message: string, error?: unknown) => Logger.error(`[${scope}] ${message}`, error),
  };
}

export function createScopedNotifier(module: string) {
  return {
    info: (action: string, details?: string) => Notifier.info({ module, action, details }),
    success: (action: string, details?: string) => Notifier.info({ module, action, details }),
    warning: (action: string, details?: string) => Notifier.warning({ module, action, details }),
    error: (action: string, error?: unknown, details?: string) => {
      const msg: NotificationMessage = { module, action, details };
      Notifier.error(msg, error);
    },
    confirm: (action: string, ...actions: string[]) =>
      Notifier.confirm({ module, action }, ...actions),
  };
}
