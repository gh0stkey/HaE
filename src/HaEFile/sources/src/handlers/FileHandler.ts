import * as vscode from 'vscode';
import { createScopedNotifier } from '../utils/logger';

const notify = createScopedNotifier('File');

export class FileHandler {
  async openFile(
    filePath: string,
    line: number,
    column: number = 0,
    match: string = ''
  ): Promise<void> {
    const uri = vscode.Uri.file(filePath);
    try {
      const document = await vscode.workspace.openTextDocument(uri);
      const editor = await vscode.window.showTextDocument(document, vscode.ViewColumn.One);
      const lineIndex = line - 1;
      const lineText = document.lineAt(lineIndex).text;
      let charColumn = Math.min(column, lineText.length);
      if (match) {
        const searchStart = Math.max(0, charColumn - match.length);
        const searchEnd = Math.min(lineText.length, charColumn + match.length * 3);
        const nearbyText = lineText.slice(searchStart, searchEnd);
        const matchIndex = nearbyText.indexOf(match);
        if (matchIndex !== -1) {
          charColumn = searchStart + matchIndex;
        } else {
          const fullLineIndex = lineText.indexOf(match);
          if (fullLineIndex !== -1) {
            charColumn = fullLineIndex;
          }
        }
      }
      const startPosition = new vscode.Position(lineIndex, charColumn);
      const endPosition = new vscode.Position(lineIndex, charColumn + match.length);
      if (match) {
        editor.selection = new vscode.Selection(startPosition, endPosition);
      } else {
        editor.selection = new vscode.Selection(startPosition, startPosition);
      }
      editor.revealRange(
        new vscode.Range(startPosition, endPosition),
        vscode.TextEditorRevealType.InCenter
      );
    } catch (error) {
      if (this._isBinaryOpenError(error)) {
        try {
          await vscode.commands.executeCommand('revealInExplorer', uri);
        } catch {}
      }
      notify.error('Open file failed', error);
    }
  }

  private _isBinaryOpenError(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error);
    return /binary and cannot be opened as text/i.test(message);
  }
}
