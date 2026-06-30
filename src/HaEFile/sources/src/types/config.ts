export interface RipgrepConfig {
  path: string;
  maxResults: number;
  scanWorkerMaxConcurrency: number;
}

export const CONFIG_NAMESPACE = 'hae';

export const CONFIG_KEYS = {
  RULES: 'rules',
  RIPGREP_PATH: 'ripgrepPath',
  ENABLE_DECORATION: 'enableDecoration',
  DECORATION_DELAY: 'decorationDelay',
  MAX_FILE_SIZE: 'maxFileSize',
  IGNORED_EXTENSIONS: 'ignoredExtensions',
  MAX_RESULTS: 'maxResults',
  SCAN_TIMEOUT: 'scanTimeout',
  SCAN_WORKER_MAX_CONCURRENCY: 'scanWorkerMaxConcurrency',
} as const;

export const CONFIG_DEFAULTS = {
  RIPGREP_PATH: '',
  ENABLE_DECORATION: true,
  DECORATION_DELAY: 500,
  MAX_FILE_SIZE: 0,
  IGNORED_EXTENSIONS: ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp'],
  MAX_RESULTS: 0,
  SCAN_TIMEOUT: 0,
  SCAN_WORKER_MAX_CONCURRENCY: 8,
  VALIDATOR_CONTEXT_WINDOW: 50,
  VALIDATOR_BULK_DEFAULT: 500,
  UI_UPDATE_INTERVAL: 300,
} as const;

export const CONFIG_LIMITS = {
  DECORATION_DELAY_MIN: 100,
  DECORATION_DELAY_MAX: 5000,
  MAX_FILE_SIZE_MIN: 0,
  MAX_FILE_SIZE_MAX: 100 * 1024 * 1024,
  MAX_RESULTS_MIN: 0,
  MAX_RESULTS_MAX: 1000000,
  SCAN_TIMEOUT_MIN: 0,
  SCAN_TIMEOUT_MAX: 600000,
  RULE_NAME_MAX_LENGTH: 200,
  GROUP_NAME_MAX_LENGTH: 200,
  WEBVIEW_INIT_DELAY: 100,
  VALIDATION_RULE_RESULTS_REFRESH_MIN_INTERVAL: 1200,
  SCAN_WORKER_MAX_CONCURRENCY_MIN: 1,
  SCAN_WORKER_STREAM_CHUNK_SIZE: 500,
} as const;
