import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom/client';
import { ActiveFilePayload } from './types';
import FileInspectorPanel from './components/FileInspectorPanel';
import ErrorBoundary from './components/ErrorBoundary';
import { vscode } from './utils/vscode';
import '@vscode/codicons/dist/codicon.css';
import './styles/base.css';
import './styles/fileInspector.css';

const FileInspectorApp: React.FC = () => {
  const [activeFileData, setActiveFileData] = useState<ActiveFilePayload | null>(null);

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      const message = event.data;
      if (message.type === 'activeFileResults') {
        setActiveFileData(message.data);
      }
    };
    window.addEventListener('message', handleMessage);
    vscode.postMessage({ command: 'webviewReady' });
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  return <FileInspectorPanel activeFileData={activeFileData} />;
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <FileInspectorApp />
    </ErrorBoundary>
  </React.StrictMode>
);
