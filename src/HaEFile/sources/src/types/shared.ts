export type RuleColor =
  | 'red'
  | 'orange'
  | 'yellow'
  | 'green'
  | 'cyan'
  | 'blue'
  | 'pink'
  | 'magenta'
  | 'gray'
  | 'none';

export type Severity = 'none' | 'low' | 'medium' | 'high';

export interface ValidatorConfig {
  command: string;
  timeout?: number;
  bulk?: number;
}

export interface ScanRule {
  id: string;
  name: string;
  group: string;
  loaded: boolean;
  regex: string;
  color: RuleColor;
  sensitive: boolean;
  validator?: ValidatorConfig;
}

export interface ScanResult {
  file: string;
  line: number;
  column: number;
  ruleId: string;
  ruleName: string;
  match: string;
  color?: RuleColor;
  severity?: Severity;
  context?: {
    before: string;
    after: string;
  };
}

export interface ValidatorInputItem {
  index: number;
  data: {
    file: string;
    line: number;
    column: number;
    match: string;
    context: {
      before: string;
      after: string;
    };
  };
}

export interface ValidatorInput {
  rule: {
    id: string;
    name: string;
    regex: string;
    group: string;
  };
  items: ValidatorInputItem[];
}

interface ValidatorOutputResult {
  index: number;
  tags: Severity;
}

export interface ValidatorOutput {
  results: ValidatorOutputResult[];
}

export interface RuleSummary {
  ruleId: string;
  name: string;
  color: string;
  count: number;
}

export interface GroupSummary {
  name: string;
  rules: RuleSummary[];
}

export interface ScanSummary {
  groups: GroupSummary[];
  duration?: number;
  validatingRuleIds: string[];
  validatingMatchValues: string[];
  workspaceRoots: string[];
}

export interface QueryRuleResultsParams {
  groupName: string;
  ruleName: string;
  searchTerm?: string;
  useRegex?: boolean;
  severities?: Severity[];
}

export interface MatchSummary {
  match: string;
  count: number;
  severity: Severity;
  color: RuleColor;
  ruleId: string;
}

export interface FileHit {
  file: string;
  line: number;
  column: number;
  severity: Severity;
}

export interface RuleResultsPayload {
  groupName: string;
  ruleName: string;
  matches: MatchSummary[];
  totalMatches: number;
  filteredResults: number;
  totalResults: number;
  queryVersion: number;
}

export interface MatchFilesPayload {
  groupName: string;
  ruleName: string;
  matchValue: string;
  files: FileHit[];
  queryVersion: number;
}

export interface ActiveFileResultGroup {
  groupName: string;
  ruleName: string;
  ruleId: string;
  color: string;
  results: ScanResult[];
}

export interface ActiveFilePayload {
  filePath: string;
  groups: ActiveFileResultGroup[];
  totalCount: number;
}

export type DataboardViewState = 'landing' | 'results';

export type ScanSessionPhase = 'idle' | 'scanning' | 'validating';

export interface ScanSessionState {
  sessionId: number;
  phase: ScanSessionPhase;
  viewState: DataboardViewState;
  hasResults: boolean;
}

export interface SettingsState {
  decorationEnabled: boolean;
  decorationDelay: number;
  maxFileSize: number;
  maxResults: number;
  scanTimeout: number;
  scanWorkerMaxConcurrency: number;
  ignoredExtensions: string[];
  ripgrepPath: string;
}

export interface StateSnapshot {
  scanSession: ScanSessionState;
  rules: ScanRule[];
  settings: SettingsState;
  summary: ScanSummary | null;
  activeFileData: ActiveFilePayload | null;
}

export type ExtensionMessage =
  | { type: 'stateSnapshot'; snapshot: StateSnapshot }
  | { type: 'scanSession'; session: ScanSessionState }
  | { type: 'scanSummary'; summary: ScanSummary }
  | { type: 'ruleResults'; ruleResults: RuleResultsPayload }
  | { type: 'matchFiles'; matchFiles: MatchFilesPayload }
  | { type: 'clearResults' }
  | { type: 'loadRules'; rules: ScanRule[] }
  | { type: 'settingsUpdate'; settings: Partial<SettingsState> }
  | { type: 'ripgrepValidation'; valid: boolean; path: string }
  | { type: 'activeFileResults'; data: ActiveFilePayload | null }
  | { type: 'viewAction'; action: 'showSettings' | 'showResults' };

export type WebviewCommand =
  | { command: 'webviewReady' }
  | { command: 'rescan' }
  | { command: 'scanWorkspace' }
  | { command: 'cancelScan' }
  | { command: 'clearResults' }
  | {
      command: 'queryRuleResults';
      groupName: string;
      ruleName: string;
      searchTerm?: string;
      useRegex?: boolean;
      severities?: Severity[];
    }
  | { command: 'openFile'; file: string; line: number; column: number; match: string }
  | { command: 'updateSeverity'; file: string; line: number; column: number; severity: Severity }
  | { command: 'revalidate'; ruleIds: string[]; matchValues?: string[] }
  | {
      command: 'queryMatchFiles';
      groupName: string;
      ruleName: string;
      matchValues: string[];
    }
  | {
      command: 'updateMatchSeverity';
      groupName: string;
      ruleName: string;
      matchValue: string;
      severity: Severity;
    }
  | { command: 'addRule'; rule: ScanRule }
  | { command: 'updateRule'; rule: ScanRule }
  | { command: 'deleteRule'; id: string }
  | { command: 'confirmDeleteRule'; id: string }
  | { command: 'deleteGroup'; groupName: string }
  | { command: 'renameGroup'; oldName: string; newName: string }
  | { command: 'importRules' }
  | { command: 'exportRules' }
  | { command: 'toggleDecoration'; enabled: boolean }
  | { command: 'setIgnoredExtensions'; extensions: string[] }
  | { command: 'setDecorationDelay'; delay: number }
  | { command: 'setMaxFileSize'; size: number }
  | { command: 'setMaxResults'; value: number }
  | { command: 'setScanTimeout'; value: number }
  | { command: 'setScanWorkerMaxConcurrency'; value: number }
  | { command: 'setRipgrepPath'; path: string }
  | { command: 'validateRipgrepPath'; path: string }
  | { command: 'showInfo'; message: string };
