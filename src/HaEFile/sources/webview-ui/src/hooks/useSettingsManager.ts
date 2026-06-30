import { useState, useCallback } from 'react';
import { vscode } from '../utils/vscode';

interface UseSettingsManagerProps {
  decorationDelay: number;
  maxFileSize: number;
  maxResults: number;
  scanTimeout: number;
  scanWorkerMaxConcurrency: number;
  ignoredExtensions: string[];
  ripgrepPath: string;
}

interface UseSettingsManagerReturn {
  delayInput: string;
  maxSizeInput: string;
  maxResultsInput: string;
  scanTimeoutInput: string;
  scanWorkerMaxConcurrencyInput: string;
  extensionsInput: string;
  ripgrepInput: string;
  setDelayInput: React.Dispatch<React.SetStateAction<string>>;
  setMaxSizeInput: React.Dispatch<React.SetStateAction<string>>;
  setMaxResultsInput: React.Dispatch<React.SetStateAction<string>>;
  setScanTimeoutInput: React.Dispatch<React.SetStateAction<string>>;
  setScanWorkerMaxConcurrencyInput: React.Dispatch<React.SetStateAction<string>>;
  setExtensionsInput: React.Dispatch<React.SetStateAction<string>>;
  setRipgrepInput: React.Dispatch<React.SetStateAction<string>>;
  toggleDecoration: (enabled: boolean) => void;
  saveDecorationDelay: () => void;
  saveMaxFileSize: () => void;
  saveMaxResults: () => void;
  saveScanTimeout: () => void;
  saveScanWorkerMaxConcurrency: () => void;
  saveIgnoredExtensions: () => void;
  saveRipgrepPath: () => void;
}

export function useSettingsManager({
  decorationDelay,
  maxFileSize,
  maxResults,
  scanTimeout,
  scanWorkerMaxConcurrency,
  ignoredExtensions,
  ripgrepPath,
}: UseSettingsManagerProps): UseSettingsManagerReturn {
  const [delayInput, setDelayInput] = useState(decorationDelay.toString());
  const [maxSizeInput, setMaxSizeInput] = useState(
    maxFileSize === 0 ? '0' : (maxFileSize / 1024 / 1024).toFixed(1)
  );
  const [maxResultsInput, setMaxResultsInput] = useState(maxResults.toString());
  const [scanTimeoutInput, setScanTimeoutInput] = useState(
    scanTimeout === 0 ? '0' : (scanTimeout / 1000).toFixed(1)
  );
  const [scanWorkerMaxConcurrencyInput, setScanWorkerMaxConcurrencyInput] = useState(
    scanWorkerMaxConcurrency.toString()
  );
  const [extensionsInput, setExtensionsInput] = useState(
    ignoredExtensions.map((ext) => ext.replace(/^\./, '')).join(', ')
  );
  const [ripgrepInput, setRipgrepInput] = useState(ripgrepPath);

  const toggleDecoration = useCallback((enabled: boolean) => {
    vscode.postMessage({
      command: 'toggleDecoration',
      enabled,
    });
  }, []);

  const saveDecorationDelay = useCallback(() => {
    const delay = parseInt(delayInput, 10);
    if (!isNaN(delay) && delay >= 100 && delay <= 5000) {
      vscode.postMessage({
        command: 'setDecorationDelay',
        delay,
      });
    }
  }, [delayInput]);

  const saveMaxFileSize = useCallback(() => {
    const sizeMB = parseFloat(maxSizeInput);
    if (!isNaN(sizeMB) && sizeMB >= 0 && sizeMB <= 100) {
      const sizeBytes = sizeMB === 0 ? 0 : Math.round(sizeMB * 1024 * 1024);
      vscode.postMessage({
        command: 'setMaxFileSize',
        size: sizeBytes,
      });
    }
  }, [maxSizeInput]);

  const saveMaxResults = useCallback(() => {
    const value = parseInt(maxResultsInput, 10);
    if (!isNaN(value) && value >= 0 && value <= 1000000) {
      vscode.postMessage({
        command: 'setMaxResults',
        value,
      });
    }
  }, [maxResultsInput]);

  const saveScanTimeout = useCallback(() => {
    const seconds = parseFloat(scanTimeoutInput);
    if (!isNaN(seconds) && seconds >= 0 && seconds <= 600) {
      const ms = Math.round(seconds * 1000);
      vscode.postMessage({
        command: 'setScanTimeout',
        value: ms,
      });
    }
  }, [scanTimeoutInput]);

  const saveScanWorkerMaxConcurrency = useCallback(() => {
    const value = parseInt(scanWorkerMaxConcurrencyInput, 10);
    if (!isNaN(value) && value >= 1) {
      vscode.postMessage({
        command: 'setScanWorkerMaxConcurrency',
        value,
      });
    }
  }, [scanWorkerMaxConcurrencyInput]);

  const saveIgnoredExtensions = useCallback(() => {
    const extensions = [
      ...new Set(
        extensionsInput
          .split(',')
          .map((ext) => ext.trim().toLowerCase())
          .filter((ext) => ext.length > 0)
          .map((ext) => (ext.startsWith('.') ? ext : `.${ext}`))
      ),
    ];

    vscode.postMessage({
      command: 'setIgnoredExtensions',
      extensions,
    });
  }, [extensionsInput]);

  const saveRipgrepPath = useCallback(() => {
    const path = ripgrepInput.trim();
    vscode.postMessage({
      command: 'setRipgrepPath',
      path,
    });
  }, [ripgrepInput]);

  return {
    delayInput,
    maxSizeInput,
    maxResultsInput,
    scanTimeoutInput,
    scanWorkerMaxConcurrencyInput,
    extensionsInput,
    ripgrepInput,
    setDelayInput,
    setMaxSizeInput,
    setMaxResultsInput,
    setScanTimeoutInput,
    setScanWorkerMaxConcurrencyInput,
    setExtensionsInput,
    setRipgrepInput,
    toggleDecoration,
    saveDecorationDelay,
    saveMaxFileSize,
    saveMaxResults,
    saveScanTimeout,
    saveScanWorkerMaxConcurrency,
    saveIgnoredExtensions,
    saveRipgrepPath,
  };
}
