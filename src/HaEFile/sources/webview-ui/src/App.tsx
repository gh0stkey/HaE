import React, { useState, useCallback, useEffect } from 'react';
import DataboardView from './components/DataboardView';
import SettingsView from './components/SettingsView';
import { ViewMode, ExtensionMessage } from './types';
import { vscode } from './utils/vscode';
import './App.css';

const getInitialViewMode = (): ViewMode => {
  const state = vscode.getState() as { viewMode?: ViewMode } | undefined;
  return state?.viewMode || 'results';
};

const App: React.FC = () => {
  const [viewMode, setViewMode] = useState<ViewMode>(getInitialViewMode);

  const logoUri = document.getElementById('root')?.dataset.logoUri || '';

  const switchView = useCallback((mode: ViewMode) => {
    setViewMode(mode);
    const currentState = vscode.getState() as Record<string, unknown> | undefined;
    vscode.setState({ ...currentState, viewMode: mode });
  }, []);

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      const message = event.data as ExtensionMessage;
      if (message.type === 'viewAction') {
        switchView(message.action === 'showSettings' ? 'settings' : 'results');
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [switchView]);

  return (
    <div className="app">
      <div className={`view-container ${viewMode === 'results' ? 'active' : 'hidden'}`}>
        <DataboardView logoUri={logoUri} />
      </div>

      <div className={`view-container ${viewMode === 'settings' ? 'active' : 'hidden'}`}>
        <SettingsView logoUri={logoUri} />
      </div>
    </div>
  );
};

export default App;
