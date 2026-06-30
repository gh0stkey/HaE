import * as vscode from 'vscode';
import { ScanResultsPersistQueue } from '../../services';
import { createScopedNotifier } from '../../utils/logger';
import { DataboardProvider } from '../../webviews';
import { ScanResultsStorage } from '../storage/ScanResultsStorage';
import { ScanWorkflowOrchestrator } from '../workflows/ScanWorkflowOrchestrator';

const notify = createScopedNotifier('Extension');

interface CommandRegistrarOptions {
  provider: DataboardProvider;
  scanWorkflow: ScanWorkflowOrchestrator;
  scanResultsStorage: ScanResultsStorage;
  scanResultsPersistQueue: ScanResultsPersistQueue;
}

export function registerExtensionCommands(
  context: vscode.ExtensionContext,
  options: CommandRegistrarOptions
): void {
  const { provider, scanWorkflow, scanResultsStorage, scanResultsPersistQueue } = options;

  context.subscriptions.push(
    vscode.commands.registerCommand('hae.openDataboard', () => {
      provider.switchToResults();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('hae.openConfig', () => {
      provider.switchToSettings();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('hae.scanFile', async (uri?: vscode.Uri) => {
      const targetPath = uri?.fsPath ?? vscode.window.activeTextEditor?.document.uri.fsPath;
      if (targetPath) {
        await scanWorkflow.scanPaths([targetPath], targetPath);
      } else {
        notify.warning('Scan file failed', 'No file selected');
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('hae.scanFolder', async (uri?: vscode.Uri) => {
      let targetPath = uri?.fsPath;
      if (!targetPath) {
        const options: vscode.OpenDialogOptions = {
          canSelectMany: false,
          canSelectFiles: false,
          canSelectFolders: true,
          openLabel: 'Select folder to scan',
        };
        const folderUri = await vscode.window.showOpenDialog(options);
        targetPath = folderUri?.[0]?.fsPath;
      }
      if (targetPath) {
        await scanWorkflow.scanPaths([targetPath], targetPath);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('hae.scanWorkspace', async () => {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders || workspaceFolders.length === 0) {
        notify.warning('Scan workspace failed', 'No workspace folder opened');

        return;
      }
      if (workspaceFolders.length === 1) {
        await scanWorkflow.scanPaths(
          [workspaceFolders[0].uri.fsPath],
          workspaceFolders[0].uri.fsPath
        );
      } else {
        await scanWorkflow.scanWorkspace(workspaceFolders);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('hae.cancelScan', () => {
      scanWorkflow.cancelOrClear();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('hae.clearStoredResults', async () => {
      scanResultsPersistQueue.clear();
      await scanResultsStorage.clear();
    })
  );
}
