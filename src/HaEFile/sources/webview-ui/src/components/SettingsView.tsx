import React, { useState } from 'react';
import { ScanRule, RuleColor, ExtensionMessage } from '../types';
import Brand from './Brand';
import { useRulesManager, useSettingsManager } from '../hooks';
import { vscode } from '../utils/vscode';
import './SettingsView.css';

interface SettingsViewProps {
  logoUri?: string;
}

type TabType = 'rules' | 'settings';

const COLORS: RuleColor[] = [
  'red',
  'orange',
  'yellow',
  'green',
  'cyan',
  'blue',
  'pink',
  'magenta',
  'gray',
  'none',
];

const SettingsView: React.FC<SettingsViewProps> = ({ logoUri }) => {
  const [rules, setRules] = useState<ScanRule[]>([]);
  const [decorationEnabled, setDecorationEnabled] = useState(true);
  const [decorationDelay, setDecorationDelay] = useState(500);
  const [maxFileSize, setMaxFileSize] = useState(0);
  const [maxResults, setMaxResults] = useState(0);
  const [scanTimeout, setScanTimeout] = useState(0);
  const [scanWorkerMaxConcurrency, setScanWorkerMaxConcurrency] = useState(8);
  const [ignoredExtensions, setIgnoredExtensions] = useState<string[]>([]);
  const [ripgrepPath, setRipgrepPath] = useState('rg');
  const [ripgrepValid, setRipgrepValid] = useState<boolean | null>(null);

  React.useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      const message = event.data as ExtensionMessage;
      switch (message.type) {
        case 'stateSnapshot': {
          const s = message.snapshot;
          setRules(s.rules);
          setDecorationEnabled(s.settings.decorationEnabled);
          setDecorationDelay(s.settings.decorationDelay);
          setMaxFileSize(s.settings.maxFileSize);
          setMaxResults(s.settings.maxResults);
          setScanTimeout(s.settings.scanTimeout);
          setScanWorkerMaxConcurrency(s.settings.scanWorkerMaxConcurrency);
          setIgnoredExtensions(s.settings.ignoredExtensions);
          setRipgrepPath(s.settings.ripgrepPath);
          vscode.postMessage({ command: 'validateRipgrepPath', path: s.settings.ripgrepPath });
          break;
        }
        case 'settingsUpdate': {
          const u = message.settings;
          if (u.decorationEnabled !== undefined) setDecorationEnabled(u.decorationEnabled);
          if (u.decorationDelay !== undefined) setDecorationDelay(u.decorationDelay);
          if (u.maxFileSize !== undefined) setMaxFileSize(u.maxFileSize);
          if (u.maxResults !== undefined) setMaxResults(u.maxResults);
          if (u.scanTimeout !== undefined) setScanTimeout(u.scanTimeout);
          if (u.scanWorkerMaxConcurrency !== undefined) {
            setScanWorkerMaxConcurrency(u.scanWorkerMaxConcurrency);
          }
          if (u.ignoredExtensions !== undefined) setIgnoredExtensions(u.ignoredExtensions);
          if (u.ripgrepPath !== undefined) setRipgrepPath(u.ripgrepPath);
          break;
        }
        case 'loadRules':
          setRules(message.rules);
          break;
        case 'ripgrepValidation':
          setRipgrepValid(message.valid);
          break;
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const [activeTab, setActiveTab] = useState<TabType>('rules');
  const [groupDropdownOpen, setGroupDropdownOpen] = useState(false);
  const [groupSearch, setGroupSearch] = useState('');
  const groupDropdownRef = React.useRef<HTMLDivElement>(null);

  const {
    editingRule,
    expandedGroups,
    searchTerm,
    colorPickerRuleId,
    editingGroupName,
    editingGroupNewName,
    regexValidation,
    filteredGroups,
    existingGroups,
    setEditingRule,
    setSearchTerm,
    setEditingGroupNewName,
    toggleGroup,
    toggleGroupEnabled,
    startEdit,
    startCreate,
    startCreateInGroup,
    cancelEdit,
    toggleRuleEnabled,
    changeRuleColor,
    toggleColorPicker,
    saveRule,
    deleteRule,
    deleteGroup,
    startEditGroup,
    cancelEditGroup,
    saveEditGroup,
    importRules,
    exportRules,
    expandAll,
  } = useRulesManager({ rules });

  const {
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
  } = useSettingsManager({
    decorationDelay,
    maxFileSize,
    maxResults,
    scanTimeout,
    scanWorkerMaxConcurrency,
    ignoredExtensions,
    ripgrepPath,
  });

  React.useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (groupDropdownRef.current && !groupDropdownRef.current.contains(e.target as Node)) {
        setGroupDropdownOpen(false);
        setGroupSearch('');
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const filteredExistingGroups = React.useMemo(() => {
    if (!groupSearch.trim()) return existingGroups;
    const search = groupSearch.toLowerCase();
    return existingGroups.filter((g) => g.toLowerCase().includes(search));
  }, [groupSearch, existingGroups]);

  React.useEffect(() => {
    setDelayInput(decorationDelay.toString());
  }, [decorationDelay, setDelayInput]);

  React.useEffect(() => {
    setMaxSizeInput(maxFileSize === 0 ? '0' : (maxFileSize / 1024 / 1024).toFixed(1));
  }, [maxFileSize, setMaxSizeInput]);

  React.useEffect(() => {
    setMaxResultsInput(maxResults.toString());
  }, [maxResults, setMaxResultsInput]);

  React.useEffect(() => {
    setScanTimeoutInput(scanTimeout === 0 ? '0' : (scanTimeout / 1000).toFixed(1));
  }, [scanTimeout, setScanTimeoutInput]);

  React.useEffect(() => {
    setScanWorkerMaxConcurrencyInput(scanWorkerMaxConcurrency.toString());
  }, [scanWorkerMaxConcurrency, setScanWorkerMaxConcurrencyInput]);

  React.useEffect(() => {
    setExtensionsInput(ignoredExtensions.map((ext) => ext.replace(/^\./, '')).join(','));
  }, [ignoredExtensions, setExtensionsInput]);

  React.useEffect(() => {
    setRipgrepInput(ripgrepPath);
  }, [ripgrepPath, setRipgrepInput]);

  React.useEffect(() => {
    if (!colorPickerRuleId) return;

    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest('.rule-color-wrapper')) {
        const fakeEvent = { stopPropagation: () => {} } as React.MouseEvent;
        toggleColorPicker(colorPickerRuleId, fakeEvent);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [colorPickerRuleId, toggleColorPicker]);

  React.useEffect(() => {
    if (searchTerm) {
      expandAll();
    }
  }, [searchTerm, expandAll]);

  return (
    <div className="settings-view">
      <Brand logoUri={logoUri} />
      <div className="settings-header">
        <div className="settings-tabs">
          <button
            className={`settings-tab ${activeTab === 'rules' ? 'active' : ''}`}
            onClick={() => setActiveTab('rules')}
          >
            <i className="codicon codicon-list-unordered"></i>
            RULES
          </button>
          <button
            className={`settings-tab ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            <i className="codicon codicon-settings-gear"></i>
            CONFIG
          </button>
        </div>
      </div>

      {activeTab === 'rules' && (
        <>
          <div className="settings-toolbar">
            <div className="toolbar-left">
              <button className="btn btn-primary" onClick={startCreate}>
                Add
              </button>
              <button className="btn" onClick={importRules}>
                Import
              </button>
              <button className="btn" onClick={exportRules}>
                Export
              </button>
            </div>
            <div className="toolbar-right">
              <div className="toolbar-search">
                <i className="codicon codicon-search search-icon"></i>
                <input
                  type="text"
                  placeholder="Search rules..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                {searchTerm && (
                  <button className="clear-search" onClick={() => setSearchTerm('')}>
                    <i className="codicon codicon-close"></i>
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className="rules-container">
            {Object.keys(filteredGroups).length === 0 ? (
              <div className="empty-state">
                <div className="empty-title">No Rules Found</div>
                <div className="empty-description">
                  {searchTerm
                    ? 'No rules match your search.'
                    : 'Click "Add Rule" to create your first rule.'}
                </div>
              </div>
            ) : (
              Object.entries(filteredGroups)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([group, groupRules]) => {
                  const allEnabled = groupRules.every((r) => r.loaded);
                  const someEnabled = groupRules.some((r) => r.loaded);
                  const isEditingThisGroup = editingGroupName === group;
                  return (
                    <div key={group} className="rule-group">
                      <div
                        className="group-header"
                        onClick={() => !isEditingThisGroup && toggleGroup(group)}
                      >
                        <label className="vscode-checkbox">
                          <input
                            type="checkbox"
                            checked={allEnabled}
                            ref={(el) => {
                              if (el) el.indeterminate = someEnabled && !allEnabled;
                            }}
                            onChange={(e) => {
                              e.stopPropagation();
                              toggleGroupEnabled(group, groupRules);
                            }}
                            onClick={(e) => e.stopPropagation()}
                          />
                          <span className="checkbox-indicator"></span>
                        </label>
                        <span className="group-toggle">
                          <i
                            className={`codicon codicon-chevron-${expandedGroups.has(group) ? 'down' : 'right'}`}
                          ></i>
                        </span>
                        {isEditingThisGroup ? (
                          <input
                            type="text"
                            className="group-name-input"
                            value={editingGroupNewName}
                            onChange={(e) => setEditingGroupNewName(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') saveEditGroup();
                              if (e.key === 'Escape') cancelEditGroup();
                            }}
                            onClick={(e) => e.stopPropagation()}
                            autoFocus
                          />
                        ) : (
                          <span className="group-name">{group}</span>
                        )}
                        {isEditingThisGroup ? (
                          <>
                            <button
                              className="group-action"
                              onClick={(e) => {
                                e.stopPropagation();
                                saveEditGroup();
                              }}
                            >
                              <i className="codicon codicon-check"></i>
                            </button>
                            <button
                              className="group-action"
                              onClick={(e) => {
                                e.stopPropagation();
                                cancelEditGroup();
                              }}
                            >
                              <i className="codicon codicon-close"></i>
                            </button>
                            <span className="group-count">{groupRules.length}</span>
                          </>
                        ) : (
                          <>
                            <button
                              className="group-action"
                              onClick={(e) => {
                                e.stopPropagation();
                                startCreateInGroup(group);
                              }}
                            >
                              <i className="codicon codicon-add"></i>
                            </button>
                            <button
                              className="group-action"
                              onClick={(e) => {
                                e.stopPropagation();
                                startEditGroup(group);
                              }}
                            >
                              <i className="codicon codicon-edit"></i>
                            </button>
                            <button
                              className="group-delete"
                              onClick={(e) => {
                                e.stopPropagation();
                                deleteGroup(group);
                              }}
                            >
                              <i className="codicon codicon-close"></i>
                            </button>
                            <span className="group-count">{groupRules.length}</span>
                          </>
                        )}
                      </div>

                      {expandedGroups.has(group) && (
                        <div className="group-rules">
                          {groupRules.map((rule) => (
                            <div
                              key={rule.id}
                              className={`rule-item ${rule.loaded ? '' : 'disabled'}`}
                            >
                              <label className="vscode-checkbox">
                                <input
                                  type="checkbox"
                                  checked={rule.loaded}
                                  onChange={() => toggleRuleEnabled(rule)}
                                />
                                <span className="checkbox-indicator"></span>
                              </label>
                              <div className="rule-color-wrapper">
                                <div
                                  className={`rule-color-dot color-${rule.color} clickable`}
                                  onClick={(e) => toggleColorPicker(rule.id, e)}
                                />
                                {colorPickerRuleId === rule.id && (
                                  <div className="inline-color-picker">
                                    {COLORS.map((color) => (
                                      <button
                                        key={color}
                                        className={`color-option color-${color} ${rule.color === color ? 'selected' : ''}`}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          changeRuleColor(rule, color);
                                        }}
                                      />
                                    ))}
                                  </div>
                                )}
                              </div>
                              <div className="rule-info">
                                <div className="rule-name">{rule.name}</div>
                                <div className="rule-regex-container">
                                  <pre className="rule-regex">{rule.regex}</pre>
                                </div>
                              </div>
                              <div className="rule-actions">
                                <button className="action-btn" onClick={() => startEdit(rule)}>
                                  <i className="codicon codicon-edit"></i>
                                </button>
                                <button className="action-btn" onClick={() => deleteRule(rule.id)}>
                                  <i className="codicon codicon-trash"></i>
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })
            )}
          </div>
        </>
      )}

      {activeTab === 'settings' && (
        <div className="settings-content">
          <div className="config-section">
            <div className="config-section-title">Decoration</div>

            <div className="config-item toggle-item">
              <div className="config-item-header">
                <label className="config-label">Decoration</label>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={decorationEnabled}
                    onChange={(e) => toggleDecoration(e.target.checked)}
                  />
                  <span className="slider"></span>
                </label>
              </div>
              <div className="config-hint">Enable real-time highlighting of data in editor</div>
            </div>

            <div className="config-item">
              <label className="config-label">Decoration Delay (milliseconds)</label>
              <div className="config-input-row">
                <input
                  type="number"
                  className="config-input"
                  value={delayInput}
                  onChange={(e) => setDelayInput(e.target.value)}
                  min="100"
                  max="5000"
                  step="100"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      saveDecorationDelay();
                    }
                  }}
                  onBlur={saveDecorationDelay}
                />
              </div>
              <div className="config-hint">Delay before applying highlighting (100-5000)</div>
            </div>
          </div>

          <div className="config-section">
            <div className="config-section-title">File Filtering</div>

            <div className="config-item">
              <label className="config-label">Max File Size (MB)</label>
              <div className="config-input-row">
                <input
                  type="number"
                  className="config-input"
                  value={maxSizeInput}
                  onChange={(e) => setMaxSizeInput(e.target.value)}
                  min="0"
                  max="100"
                  step="0.1"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      saveMaxFileSize();
                    }
                  }}
                  onBlur={saveMaxFileSize}
                />
              </div>
              <div className="config-hint">
                Files larger than this will be skipped during scanning and highlighting (0 = no
                limit)
              </div>
            </div>

            <div className="config-item">
              <label className="config-label">Ignored Extensions</label>
              <div className="config-input-row">
                <input
                  type="text"
                  className="config-input wide"
                  value={extensionsInput}
                  onChange={(e) => setExtensionsInput(e.target.value)}
                  placeholder="png,jpg,gif..."
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      saveIgnoredExtensions();
                      (e.target as HTMLInputElement).blur();
                    }
                  }}
                  onBlur={saveIgnoredExtensions}
                />
              </div>
              <div className="config-hint">
                Files with these extensions will be skipped during scanning (e.g., png,jpg,gif)
              </div>
            </div>
          </div>

          <div className="config-section">
            <div className="config-section-title">Ripgrep</div>
            <div className="config-item">
              <div className="config-label-row">
                <label className="config-label">Ripgrep Path</label>
                {ripgrepValid !== null && (
                  <span className={`ripgrep-status ${ripgrepValid ? 'valid' : 'invalid'}`}>
                    {ripgrepValid ? 'Available' : 'Unavailable'}
                  </span>
                )}
              </div>
              <div className="config-input-row">
                <input
                  type="text"
                  className={`config-input wide ${ripgrepValid === false ? 'error' : ''}`}
                  value={ripgrepInput}
                  onChange={(e) => {
                    setRipgrepInput(e.target.value);
                  }}
                  placeholder="rg"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      saveRipgrepPath();
                      vscode.postMessage({
                        command: 'validateRipgrepPath',
                        path: ripgrepInput.trim() || 'rg',
                      });
                      (e.target as HTMLInputElement).blur();
                    }
                  }}
                  onBlur={() => {
                    saveRipgrepPath();
                    vscode.postMessage({
                      command: 'validateRipgrepPath',
                      path: ripgrepInput.trim() || 'rg',
                    });
                  }}
                />
              </div>
              <div className="config-hint">Path to ripgrep executable</div>
            </div>

            <div className="config-item">
              <label className="config-label">Max Results</label>
              <div className="config-input-row">
                <input
                  type="number"
                  className="config-input"
                  value={maxResultsInput}
                  onChange={(e) => setMaxResultsInput(e.target.value)}
                  min="0"
                  max="1000000"
                  step="100"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      saveMaxResults();
                    }
                  }}
                  onBlur={saveMaxResults}
                />
              </div>
              <div className="config-hint">
                Maximum number of scan results to return (0 = no limit)
              </div>
            </div>

            <div className="config-item">
              <label className="config-label">Scan Timeout (seconds)</label>
              <div className="config-input-row">
                <input
                  type="number"
                  className="config-input"
                  value={scanTimeoutInput}
                  onChange={(e) => setScanTimeoutInput(e.target.value)}
                  min="0"
                  max="600"
                  step="5"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      saveScanTimeout();
                    }
                  }}
                  onBlur={saveScanTimeout}
                />
              </div>
              <div className="config-hint">
                Maximum time allowed for scan operation (0 = no limit)
              </div>
            </div>

            <div className="config-item">
              <label className="config-label">Worker Concurrency</label>
              <div className="config-input-row">
                <input
                  type="number"
                  className="config-input"
                  value={scanWorkerMaxConcurrencyInput}
                  onChange={(e) => setScanWorkerMaxConcurrencyInput(e.target.value)}
                  min="1"
                  step="1"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      saveScanWorkerMaxConcurrency();
                    }
                  }}
                  onBlur={saveScanWorkerMaxConcurrency}
                />
              </div>
              <div className="config-hint">Maximum concurrent scan worker threads</div>
            </div>
          </div>
        </div>
      )}

      {editingRule && (
        <div className="edit-overlay">
          <div className="edit-dialog">
            <div className="edit-header">
              <h2>{editingRule.isNew ? 'Add Rule' : 'Edit Rule'}</h2>
              <button className="close-btn" onClick={cancelEdit}>
                <i className="codicon codicon-close"></i>
              </button>
            </div>
            <div className="edit-body">
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={editingRule.name || ''}
                  onChange={(e) => setEditingRule((prev) => ({ ...prev!, name: e.target.value }))}
                  placeholder="Rule name"
                />
              </div>
              <div className="form-group">
                <label>Group *</label>
                <div className="combobox" ref={groupDropdownRef}>
                  <button
                    className="combobox-trigger"
                    onClick={() => setGroupDropdownOpen(!groupDropdownOpen)}
                    type="button"
                  >
                    <span>{editingRule.group || 'Select or create group...'}</span>
                    <i
                      className={`codicon codicon-chevron-${groupDropdownOpen ? 'up' : 'down'}`}
                    ></i>
                  </button>
                  {groupDropdownOpen && (
                    <div className="combobox-dropdown">
                      <div className="combobox-search">
                        <i className="codicon codicon-search"></i>
                        <input
                          type="text"
                          placeholder="Search or create new group..."
                          value={groupSearch}
                          onChange={(e) => setGroupSearch(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && groupSearch.trim()) {
                              setEditingRule((prev) => ({ ...prev!, group: groupSearch.trim() }));
                              setGroupDropdownOpen(false);
                              setGroupSearch('');
                            }
                          }}
                          autoFocus
                        />
                      </div>
                      <div className="combobox-options">
                        {groupSearch.trim() &&
                          !filteredExistingGroups.includes(groupSearch.trim()) && (
                            <button
                              className="combobox-option"
                              onClick={() => {
                                setEditingRule((prev) => ({ ...prev!, group: groupSearch.trim() }));
                                setGroupDropdownOpen(false);
                                setGroupSearch('');
                              }}
                              type="button"
                            >
                              <i className="codicon codicon-add"></i>
                              Create new: {groupSearch.trim()}
                            </button>
                          )}
                        {filteredExistingGroups.length > 0
                          ? filteredExistingGroups.map((group) => (
                              <button
                                key={group}
                                className={`combobox-option ${editingRule.group === group ? 'selected' : ''}`}
                                onClick={() => {
                                  setEditingRule((prev) => ({ ...prev!, group }));
                                  setGroupDropdownOpen(false);
                                  setGroupSearch('');
                                }}
                                type="button"
                              >
                                {group}
                                {editingRule.group === group && (
                                  <i className="codicon codicon-check"></i>
                                )}
                              </button>
                            ))
                          : !groupSearch.trim() && (
                              <div className="combobox-empty">
                                No groups yet. Enter a name to create one.
                              </div>
                            )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
              <div className="form-group">
                <div className="label-row">
                  <label>Regex Pattern *</label>
                  {editingRule.regex && (
                    <span
                      className={`regex-status ${regexValidation.isValid ? 'valid' : 'invalid'}`}
                    >
                      {regexValidation.isValid ? 'Valid' : 'Invalid'}
                    </span>
                  )}
                  <button
                    type="button"
                    className={`case-sensitive-btn ${editingRule.sensitive ? 'active' : ''}`}
                    onClick={() =>
                      setEditingRule((prev) => ({ ...prev!, sensitive: !prev?.sensitive }))
                    }
                  >
                    <i className="codicon codicon-case-sensitive"></i>
                  </button>
                </div>
                <textarea
                  value={editingRule.regex || ''}
                  onChange={(e) => setEditingRule((prev) => ({ ...prev!, regex: e.target.value }))}
                  placeholder="Regular expression pattern"
                  className={`code-input ${editingRule.regex && !regexValidation.isValid ? 'invalid' : ''} ${editingRule.regex && regexValidation.isValid ? 'valid' : ''}`}
                  rows={3}
                  spellCheck={false}
                />
                {editingRule.regex && !regexValidation.isValid && regexValidation.error && (
                  <span className="regex-error-hint">{regexValidation.error}</span>
                )}
              </div>
              <div className="form-group">
                <label>Validator Command</label>
                <textarea
                  value={editingRule.validatorCommand || ''}
                  onChange={(e) =>
                    setEditingRule((prev) => ({ ...prev!, validatorCommand: e.target.value }))
                  }
                  placeholder="Validator command that receives json data via stdin"
                  className="code-input"
                  rows={3}
                  spellCheck={false}
                />
              </div>
              <div className="form-group">
                <label>Validator Timeout (ms)</label>
                <input
                  type="number"
                  value={editingRule.validatorTimeout ?? ''}
                  onChange={(e) => {
                    const val = e.target.value;
                    setEditingRule((prev) => ({
                      ...prev!,
                      validatorTimeout: val === '' ? undefined : parseInt(val, 10),
                    }));
                  }}
                  placeholder="5000"
                  min={1000}
                  max={60000}
                />
              </div>
              <div className="form-group">
                <label>Validator Bulk</label>
                <input
                  type="number"
                  value={editingRule.validatorBulk ?? ''}
                  onChange={(e) => {
                    const val = e.target.value;
                    setEditingRule((prev) => ({
                      ...prev!,
                      validatorBulk: val === '' ? undefined : parseInt(val, 10),
                    }));
                  }}
                  placeholder="500"
                  min={1}
                  max={50000}
                />
              </div>
              <div className="form-group">
                <label>Highlight Color</label>
                <div className="color-picker">
                  {COLORS.map((color) => (
                    <button
                      key={color}
                      className={`color-option color-${color} ${editingRule.color === color ? 'selected' : ''}`}
                      onClick={() => setEditingRule({ ...editingRule, color })}
                    />
                  ))}
                </div>
              </div>
            </div>
            <div className="edit-footer">
              <button className="btn" onClick={cancelEdit}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={saveRule}
                disabled={!editingRule.name || !editingRule.regex || !regexValidation.isValid}
              >
                {editingRule.isNew ? 'Create' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SettingsView;
