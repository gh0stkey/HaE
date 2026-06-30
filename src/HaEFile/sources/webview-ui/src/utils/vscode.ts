import type { WebviewApi } from 'vscode-webview';

class VSCodeAPIWrapper {
  private readonly vsCodeApi: WebviewApi<unknown> | undefined;

  constructor() {
    if (typeof acquireVsCodeApi === 'function') {
      this.vsCodeApi = acquireVsCodeApi();
    }
  }

  public postMessage(message: unknown) {
    if (this.vsCodeApi) {
      this.vsCodeApi.postMessage(message);
    }
  }

  public openFile(file: string, line: number, column: number = 0, match: string = ''): void {
    this.postMessage({
      command: 'openFile',
      file,
      line,
      column,
      match,
    });
  }

  public async copyTextWithInfo(
    text: string,
    message: string = 'Copied to clipboard'
  ): Promise<void> {
    await navigator.clipboard.writeText(text);
    this.postMessage({ command: 'showInfo', message });
  }

  public getState(): unknown | undefined {
    if (this.vsCodeApi) {
      return this.vsCodeApi.getState();
    } else {
      const state = localStorage.getItem('vscodeState');
      return state ? JSON.parse(state) : undefined;
    }
  }

  public setState<T extends unknown | undefined>(newState: T): T {
    if (this.vsCodeApi) {
      return this.vsCodeApi.setState(newState);
    } else {
      localStorage.setItem('vscodeState', JSON.stringify(newState));
      return newState;
    }
  }
}

export const vscode = new VSCodeAPIWrapper();
