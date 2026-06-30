import * as vscode from 'vscode';
import {
  ConfigService,
  RuleService,
  ScanService,
  DecorationService,
  ValidatorService,
  ScanResultsPersistQueue,
  JobController,
} from './services';
import {
  registerExtensionCommands,
  ScanResultsStorage,
  ScanWorkflowOrchestrator,
} from './application';
import { DataboardProvider, FileInspectorProvider } from './webviews';
import { Logger, createScopedNotifier } from './utils/logger';

const notify = createScopedNotifier('Extension');

const VALIDATION_PERSIST_DEBOUNCE_MS = 1200;

interface ExtensionState {
  decorationService: DecorationService;
  scanService: ScanService;
  scanWorkflow: ScanWorkflowOrchestrator;
  scanResultsPersistQueue: ScanResultsPersistQueue;
}

let state: ExtensionState | undefined;

export function activate(context: vscode.ExtensionContext): void {
  Logger.initialize();
  Logger.info('HaE extension is now active!');

  const scanResultsStorage = new ScanResultsStorage(context);
  const scanResultsPersistQueue = new ScanResultsPersistQueue(
    (request) =>
      scanResultsStorage.save(
        request.paths,
        request.displayName,
        request.results,
        request.duration
      ),
    VALIDATION_PERSIST_DEBOUNCE_MS
  );
  context.subscriptions.push(scanResultsPersistQueue);

  const ruleService = RuleService.getInstance();
  const scanService = ScanService.getInstance();
  const decorationService = DecorationService.getInstance();
  decorationService.initialize(context);
  const provider = new DataboardProvider(context.extensionUri);
  const fileInspectorProvider = new FileInspectorProvider(context.extensionUri);
  fileInspectorProvider.setDataSource(() => decorationService.getLastFileResults());
  const scanWorkflow = new ScanWorkflowOrchestrator(
    provider,
    ruleService,
    scanService,
    scanResultsPersistQueue
  );

  decorationService.onFileResults((payload) => {
    provider.sendActiveFilePayload(payload);
    fileInspectorProvider.sendPayload(payload);
  });

  provider.onSeverityChanged((results) => {
    scanResultsPersistQueue.enqueue(results);
  });
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(DataboardProvider.viewId, provider)
  );
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(FileInspectorProvider.viewId, fileInspectorProvider)
  );
  state = {
    decorationService,
    scanService,
    scanWorkflow,
    scanResultsPersistQueue,
  };
  registerExtensionCommands(context, {
    provider,
    scanWorkflow,
    scanResultsStorage,
    scanResultsPersistQueue,
  });
  void importBuiltinRulesIfEmpty(context, ruleService);
  void checkRipgrepAvailability(scanService, provider);
  void restoreScanResults(provider, scanResultsStorage, scanResultsPersistQueue);
}

async function restoreScanResults(
  provider: DataboardProvider,
  scanResultsStorage: ScanResultsStorage,
  scanResultsPersistQueue: ScanResultsPersistQueue
): Promise<void> {
  const restored = await scanResultsStorage.restore();
  if (!restored) {
    return;
  }

  provider.updateResults(restored.results, restored.duration, restored.paths);
  scanResultsPersistQueue.setMetadata(restored.paths, restored.displayName, restored.duration);
  Logger.info(`Restored ${restored.totalResults} results from ${restored.displayName}`);
}

async function checkRipgrepAvailability(
  scanService: ScanService,
  provider: DataboardProvider
): Promise<void> {
  const isAvailable = await scanService.testRipgrepPath();
  if (!isAvailable) {
    const selection = await notify.confirm(
      'Ripgrep is not available, please configure the ripgrep path',
      'Open Settings'
    );
    if (selection === 'Open Settings') {
      provider.switchToSettings();
    }
  }
}

async function importBuiltinRulesIfEmpty(
  context: vscode.ExtensionContext,
  ruleService: RuleService
): Promise<void> {
  const rules = ruleService.getRules();
  if (rules.length === 0) {
    try {
      const builtinRulesUri = vscode.Uri.joinPath(context.extensionUri, 'resources', 'Rules.yml');
      const content = await vscode.workspace.fs.readFile(builtinRulesUri);
      const yamlContent = Buffer.from(content).toString('utf8');
      const result = ruleService.importRulesFromYAML(yamlContent);
      if (result.success) {
        await ruleService.saveRules();
        Logger.info(`Imported ${result.count} built-in rules`);
      } else {
        Logger.error('Failed to import built-in rules', result.error);
      }
    } catch (error) {
      Logger.error('Failed to read built-in rules file', error);
    }
  }
}

export function deactivate(): void {
  Logger.info('Deactivating HaE extension');
  if (state) {
    state.scanWorkflow.dispose();
    state.scanResultsPersistQueue.dispose();
    state.decorationService.dispose();
    state.scanService.dispose();
  }
  JobController.getInstance().dispose();
  RuleService.getInstance().dispose();
  ValidatorService.getInstance().dispose();
  ConfigService.getInstance().dispose();
  Logger.dispose();
  state = undefined;
}
