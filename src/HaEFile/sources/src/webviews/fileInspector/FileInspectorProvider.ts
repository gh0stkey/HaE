import * as vscode from 'vscode';
import { ActiveFilePayload } from '../../types';
import { FileHandler } from '../../handlers';
import { isValidFilePath } from '../../utils/validation';

const INIT_DELAY = 150;

export class FileInspectorProvider implements vscode.WebviewViewProvider {
  public static readonly viewId = 'hae.fileInspector';

  private _view?: vscode.WebviewView;
  private _lastPayload: ActiveFilePayload | null = null;
  private _initTimer?: ReturnType<typeof setTimeout>;
  private _getActiveData?: () => ActiveFilePayload | undefined;
  private readonly _fileHandler = new FileHandler();

  constructor(private readonly _extensionUri: vscode.Uri) {}

  public setDataSource(getter: () => ActiveFilePayload | undefined): void {
    this._getActiveData = getter;
  }

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ): void {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtml(webviewView.webview);

    webviewView.webview.onDidReceiveMessage((message) => {
      if (message.command === 'webviewReady') {
        this._pushData();
      } else if (message.command === 'openFile') {
        if (
          !isValidFilePath(message.file) ||
          typeof message.line !== 'number' ||
          !Number.isFinite(message.line) ||
          message.line < 1
        ) {
          return;
        }
        const column =
          typeof message.column === 'number' &&
          Number.isFinite(message.column) &&
          message.column >= 0
            ? Math.floor(message.column)
            : 0;
        const match = typeof message.match === 'string' ? message.match : '';
        void this._fileHandler.openFile(message.file, message.line, column, match);
      } else if (message.command === 'showInfo') {
        void vscode.window.showInformationMessage(message.message || 'Done');
      }
    });

    this._scheduleInitialPush();

    webviewView.onDidChangeVisibility(() => {
      this._clearInitTimer();
      if (webviewView.visible) {
        this._scheduleInitialPush();
      }
    });
  }

  public sendPayload(payload: ActiveFilePayload | null): void {
    this._lastPayload = payload;
    if (this._view?.visible) {
      this._postPayload(payload);
    }
  }

  private _pushData(): void {
    this._clearInitTimer();
    const data = this._lastPayload ?? this._getActiveData?.() ?? null;
    this._postPayload(data);
  }

  private _scheduleInitialPush(): void {
    this._clearInitTimer();
    this._initTimer = setTimeout(() => {
      this._initTimer = undefined;
      this._pushData();
    }, INIT_DELAY);
  }

  private _clearInitTimer(): void {
    if (this._initTimer) {
      clearTimeout(this._initTimer);
      this._initTimer = undefined;
    }
  }

  private _postPayload(payload: ActiveFilePayload | null): void {
    this._view?.webview.postMessage({ type: 'activeFileResults', data: payload });
  }

  private _getHtml(webview: vscode.Webview): string {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'webview-ui', 'dist', 'assets', 'fileInspector.js')
    );
    const styleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'webview-ui', 'dist', 'assets', 'fileInspector.css')
    );
    const baseStyleUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, 'webview-ui', 'dist', 'assets', 'base.css')
    );

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; font-src ${webview.cspSource}; script-src ${webview.cspSource};">
    <title>HaE - File Inspector</title>
    <link rel="stylesheet" href="${baseStyleUri}">
    <link rel="stylesheet" href="${styleUri}">
</head>
<body>
    <div id="root"></div>
    <script type="module" src="${scriptUri}"></script>
</body>
</html>`;
  }
}
