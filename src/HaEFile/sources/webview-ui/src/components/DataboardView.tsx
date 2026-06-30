import React from 'react';
import { Severity, ScanSummary, ScanSessionState, ExtensionMessage, ScanRule } from '../types';
import Brand from './Brand';
import LandingView from './LandingView';
import { useDataboard, TreeNode, TocItem, FlatNode, useResize } from '../hooks';
import { vscode } from '../utils/vscode';
import { useVirtualizer } from '@tanstack/react-virtual';
import '../styles/detailHeader.css';
import './DataboardView.css';

const SEVERITIES: Severity[] = ['high', 'medium', 'low', 'none'];
const DEFAULT_ROW_HEIGHT = 32;
const TOOLTIP_OFFSET_X = 14;
const TOOLTIP_OFFSET_Y = 18;
const TOOLTIP_SHOW_DELAY_MS = 1000;

const DEFAULT_SCAN_SESSION: ScanSessionState = {
  sessionId: 0,
  phase: 'idle',
  viewState: 'landing',
  hasResults: false,
};

interface PersistedDataboardState {
  scanSession: ScanSessionState;
  summary: ScanSummary | null;
  selectedRule: { groupName: string; ruleName: string } | null;
  decorationEnabled: boolean;
}

const loadPersistedDataboard = (): PersistedDataboardState | undefined => {
  const state = vscode.getState() as { databoard?: PersistedDataboardState } | undefined;
  return state?.databoard;
};

const persistDataboard = (data: PersistedDataboardState): void => {
  const current = vscode.getState() as Record<string, unknown> | undefined;
  vscode.setState({ ...current, databoard: data });
};

const formatDuration = (ms: number | undefined): string => {
  if (ms === undefined) return '';
  if (ms < 1000) return `${(ms / 1000).toFixed(1)}s`;
  const totalSeconds = Math.round(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) return `${seconds}s`;
  if (minutes < 60) return `${minutes}m ${seconds}s`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return `${hours}h ${remainingMinutes}m`;
};

interface DataboardViewProps {
  logoUri?: string;
}

const DataboardView: React.FC<DataboardViewProps> = ({ logoUri }) => {
  const [persisted] = React.useState(loadPersistedDataboard);

  const [scanSession, setScanSession] = React.useState<ScanSessionState>(
    persisted?.scanSession
      ? { ...persisted.scanSession, phase: 'idle' as const }
      : DEFAULT_SCAN_SESSION
  );
  const [summary, setSummary] = React.useState<ScanSummary | null>(persisted?.summary ?? null);
  const [selectedRule, setSelectedRule] = React.useState<{
    groupName: string;
    ruleName: string;
  } | null>(persisted?.selectedRule ?? null);
  const [validatableRuleIds, setValidatableRuleIds] = React.useState<string[]>([]);
  const [decorationEnabled, setDecorationEnabled] = React.useState(
    persisted?.decorationEnabled ?? false
  );

  React.useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      const message = event.data as ExtensionMessage;
      switch (message.type) {
        case 'stateSnapshot': {
          const s = message.snapshot;
          setScanSession(s.scanSession);
          setSummary(s.summary);
          setDecorationEnabled(s.settings.decorationEnabled);
          setValidatableRuleIds(
            s.rules.filter((r: ScanRule) => r.validator?.command).map((r: ScanRule) => r.id)
          );
          break;
        }
        case 'scanSession':
          setScanSession(message.session);
          break;
        case 'scanSummary':
          setSummary(message.summary);
          break;
        case 'clearResults':
          setSummary(null);
          setSelectedRule(null);
          setScanSession((current) => ({
            ...current,
            phase: 'idle',
            viewState: 'landing',
            hasResults: false,
          }));
          break;
        case 'loadRules':
          setValidatableRuleIds(
            message.rules.filter((r: ScanRule) => r.validator?.command).map((r: ScanRule) => r.id)
          );
          break;
        case 'settingsUpdate':
          if (message.settings.decorationEnabled !== undefined) {
            setDecorationEnabled(message.settings.decorationEnabled);
          }
          break;
      }
    };
    window.addEventListener('message', handleMessage);
    vscode.postMessage({ command: 'webviewReady' });
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  React.useEffect(() => {
    persistDataboard({ scanSession, summary, selectedRule, decorationEnabled });
  }, [scanSession, summary, selectedRule, decorationEnabled]);

  const viewState = scanSession.viewState;
  const scanPhase = scanSession.phase;
  const isScanning = scanPhase !== 'idle';
  const isLanding = viewState === 'landing';

  const [severityPickerKey, setSeverityPickerKey] = React.useState<string | null>(null);
  const [hoverTooltip, setHoverTooltip] = React.useState<{
    text: string;
    x: number;
    y: number;
  } | null>(null);
  const tooltipShowTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const tooltipPendingRef = React.useRef<{ text: string; x: number; y: number } | null>(null);
  const { width: tocWidth, handleResizeStart } = useResize({ initialWidth: 200 });
  const [expandedGroups, setExpandedGroups] = React.useState<Set<string>>(new Set());
  const contentRef = React.useRef<HTMLDivElement>(null);

  const {
    searchTerm,
    useRegex,
    processedTree,
    visibleNodes,
    selectedSeverities,
    toggleSeverity,
    filteredResults: ruleFilteredResults,
    totalResults: ruleTotalResults,
    stats,
    tocItems,
    setSearchTerm,
    setUseRegex,
    toggleNode,
    openFile,
    rescan,
    scanWorkspace,
    clearResults,
    copyMatches,
    revalidate,
  } = useDataboard({
    summary,
    selectedRule,
    workspaceRoots: summary?.workspaceRoots,
    isScanning,
  });

  React.useEffect(() => {
    const groupIds = tocItems.map((item) => item.id);
    setExpandedGroups((prev) => {
      if (groupIds.length === 0) {
        return new Set();
      }
      if (prev.size === 0) {
        return new Set(groupIds);
      }
      const next = new Set<string>();
      for (const id of groupIds) {
        if (prev.has(id)) {
          next.add(id);
        }
      }
      return next;
    });
  }, [tocItems]);

  const virtualizer = useVirtualizer({
    count: visibleNodes.length,
    getScrollElement: () => contentRef.current,
    estimateSize: () => DEFAULT_ROW_HEIGHT,
    measureElement: (element) => element.getBoundingClientRect().height,
    overscan: 20,
  });

  React.useEffect(() => {
    if (!selectedRule || !contentRef.current) {
      return;
    }

    contentRef.current.scrollTop = 0;
  }, [selectedRule?.groupName, selectedRule?.ruleName]);

  React.useEffect(() => {
    if (!selectedRule || !contentRef.current || visibleNodes.length === 0) {
      return;
    }

    const rafId = requestAnimationFrame(() => {
      virtualizer.measure();
    });

    return () => {
      cancelAnimationFrame(rafId);
    };
  }, [selectedRule?.groupName, selectedRule?.ruleName, visibleNodes.length, virtualizer]);

  React.useEffect(() => {
    const handleClickOutside = () => setSeverityPickerKey(null);
    if (severityPickerKey) {
      document.addEventListener('click', handleClickOutside);
      return () => document.removeEventListener('click', handleClickOutside);
    }
  }, [severityPickerKey]);

  React.useEffect(() => {
    return () => {
      if (tooltipShowTimerRef.current) {
        clearTimeout(tooltipShowTimerRef.current);
        tooltipShowTimerRef.current = null;
      }
      tooltipPendingRef.current = null;
    };
  }, []);

  const showHoverTooltip = React.useCallback(
    (event: React.MouseEvent<HTMLElement>, text: string) => {
      if (!text) {
        return;
      }
      if (tooltipShowTimerRef.current) {
        clearTimeout(tooltipShowTimerRef.current);
        tooltipShowTimerRef.current = null;
      }

      const pendingTooltip = {
        text,
        x: Math.min(event.clientX + TOOLTIP_OFFSET_X, window.innerWidth - 20),
        y: Math.min(event.clientY + TOOLTIP_OFFSET_Y, window.innerHeight - 20),
      };

      tooltipPendingRef.current = pendingTooltip;
      setHoverTooltip(null);

      tooltipShowTimerRef.current = setTimeout(() => {
        if (tooltipPendingRef.current) {
          setHoverTooltip(tooltipPendingRef.current);
        }
        tooltipShowTimerRef.current = null;
      }, TOOLTIP_SHOW_DELAY_MS);
    },
    []
  );

  const moveHoverTooltip = React.useCallback((event: React.MouseEvent<HTMLElement>) => {
    if (tooltipPendingRef.current) {
      tooltipPendingRef.current = {
        ...tooltipPendingRef.current,
        x: Math.min(event.clientX + TOOLTIP_OFFSET_X, window.innerWidth - 20),
        y: Math.min(event.clientY + TOOLTIP_OFFSET_Y, window.innerHeight - 20),
      };
    }
  }, []);

  const hideHoverTooltip = React.useCallback(() => {
    if (tooltipShowTimerRef.current) {
      clearTimeout(tooltipShowTimerRef.current);
      tooltipShowTimerRef.current = null;
    }
    tooltipPendingRef.current = null;
    setHoverTooltip(null);
  }, []);

  const hoverTooltipHandlers = React.useCallback(
    (text: string) => ({
      onMouseEnter: (event: React.MouseEvent<HTMLElement>) => showHoverTooltip(event, text),
      onMouseMove: moveHoverTooltip,
      onMouseLeave: hideHoverTooltip,
    }),
    [hideHoverTooltip, moveHoverTooltip, showHoverTooltip]
  );

  const handleSeverityChange = (node: TreeNode, newSeverity: Severity) => {
    if (selectedRule && node.type === 'match') {
      vscode.postMessage({
        command: 'updateMatchSeverity',
        groupName: selectedRule.groupName,
        ruleName: selectedRule.ruleName,
        matchValue: node.name,
        severity: newSeverity,
      });
    }
    setSeverityPickerKey(null);
  };

  const handleTocClick = (item: TocItem) => {
    if (item.type === 'group') {
      setExpandedGroups((prev) => {
        const next = new Set(prev);
        if (next.has(item.id)) {
          next.delete(item.id);
        } else {
          next.add(item.id);
        }
        return next;
      });
    } else if (item.type === 'rule' && item.groupName && item.ruleName) {
      setSelectedRule({ groupName: item.groupName, ruleName: item.ruleName });
    }
  };

  const renderTocItem = (item: TocItem, depth: number = 0): React.ReactNode => {
    const isSelected =
      item.type === 'rule' &&
      selectedRule?.groupName === item.groupName &&
      selectedRule?.ruleName === item.ruleName;
    const isGroupExpanded = item.type === 'group' && expandedGroups.has(item.id);

    return (
      <div key={item.id}>
        <div
          className={`toc-item toc-${item.type} ${isSelected ? 'selected' : ''}`}
          style={{ paddingLeft: depth * 12 + 8 }}
          onClick={() => handleTocClick(item)}
        >
          {item.type === 'group' && (
            <span className="tree-toggle">
              <i className={`codicon codicon-chevron-${isGroupExpanded ? 'down' : 'right'}`}></i>
            </span>
          )}
          {item.type === 'rule' && (
            <span className={`hae-color-dot color-${item.color || 'gray'}`} />
          )}
          <span className="toc-name">{item.name}</span>
          {item.type === 'rule' &&
            item.ruleId &&
            summary?.validatingRuleIds?.includes(item.ruleId) && (
              <span className="validating-spinner" />
            )}
          <span className="hae-badge">{item.count}</span>
        </div>
        {item.type === 'group' && isGroupExpanded && item.children && item.children.length > 0 && (
          <div>{item.children.map((child) => renderTocItem(child, depth + 1))}</div>
        )}
      </div>
    );
  };

  const nodeHasValidator = (node: TreeNode): boolean => {
    if (node.ruleId) {
      return validatableRuleIds.includes(node.ruleId);
    }
    return node.children?.some((child) => nodeHasValidator(child)) ?? false;
  };

  const renderNodeActionButtons = (node: TreeNode): React.ReactNode => (
    <span className="btn-group">
      <button
        className="copy-btn"
        disabled={!nodeHasValidator(node)}
        onClick={(e) => {
          e.stopPropagation();
          revalidate(node);
        }}
      >
        <i className="codicon codicon-sparkle"></i>
      </button>
      <button className="copy-btn" onClick={(e) => copyMatches(node, e)}>
        <i className="codicon codicon-copy"></i>
      </button>
    </span>
  );

  const renderHeader = (showStats: boolean): React.ReactNode => (
    <div className="databoard-header">
      <div className="header-top">
        <div className="header-title">
          <h1>DATABOARD</h1>
        </div>
        <div className="header-meta">
          {showStats && (
            <div className="header-stats">
              <span>{stats.totalMatches} MATCHES</span>
              <span className="stat-sep">•</span>
              <span>{stats.totalGroups} GROUPS</span>
              {summary?.duration !== undefined && (
                <>
                  <span className="stat-sep">•</span>
                  <span>{formatDuration(summary.duration)} DURATION</span>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const renderFlatNode = (flatNode: FlatNode): React.ReactNode => {
    const { node, key, depth, hasChildren, isExpanded } = flatNode;
    const indent = depth * 8;

    if (node.type === 'file') {
      if (key.endsWith('/__loading')) {
        return (
          <div
            className="tree-item tree-file-leaf loading-placeholder"
            style={{ paddingLeft: indent + 8, opacity: 0.5 }}
          >
            <span className="validating-spinner" />
            <span className="file-path">Loading...</span>
          </div>
        );
      }
      const lineCol = node.result ? `${node.result.line}:${node.result.column + 1}` : '';
      return (
        <div
          className="tree-item tree-file-leaf"
          style={{ paddingLeft: indent + 8 }}
          onClick={() =>
            node.result &&
            openFile(node.result.file, node.result.line, node.result.column, node.result.match)
          }
        >
          <span className="file-path" {...hoverTooltipHandlers(node.filePath || node.name)}>
            {node.name}
          </span>
          <span className="file-line-col">{lineCol}</span>
          <button
            className="copy-btn"
            onClick={(e) => {
              e.stopPropagation();
              if (node.filePath) {
                void vscode.copyTextWithInfo(node.filePath, 'File path copied to clipboard');
              }
            }}
          >
            <i className="codicon codicon-copy"></i>
          </button>
        </div>
      );
    }

    if (node.type === 'match') {
      const severity = node.severity;
      return (
        <div
          className={`tree-item tree-match ${isExpanded ? 'expanded' : ''}`}
          style={{ paddingLeft: indent }}
          onClick={() => {
            if (hasChildren) {
              toggleNode(key);
            }
          }}
        >
          {hasChildren && (
            <span className="tree-toggle">
              <i className={`codicon codicon-chevron-${isExpanded ? 'down' : 'right'}`}></i>
            </span>
          )}
          <div className="severity-wrapper">
            <span
              className={`severity-badge severity-${severity || 'none'} clickable`}
              onClick={(e) => {
                e.stopPropagation();
                setSeverityPickerKey(severityPickerKey === key ? null : key);
              }}
            >
              {(severity || 'none').charAt(0).toUpperCase()}
            </span>
            {severityPickerKey === key && (
              <div className="severity-picker" onClick={(e) => e.stopPropagation()}>
                {SEVERITIES.map((sev) => (
                  <button
                    key={sev}
                    className={`severity-option severity-${sev} ${severity === sev ? 'selected' : ''}`}
                    onClick={() => handleSeverityChange(node, sev)}
                  >
                    {sev.charAt(0).toUpperCase()}
                  </button>
                ))}
              </div>
            )}
          </div>
          <span className="match-text" {...hoverTooltipHandlers(node.name)}>
            {node.name}
          </span>
          {summary?.validatingMatchValues?.includes(node.name) && (
            <span className="validating-spinner" />
          )}
          <span className="hae-badge tree-count">{node.count}</span>
          {renderNodeActionButtons(node)}
        </div>
      );
    }

    return (
      <div
        className={`tree-item tree-${node.type} ${isExpanded ? 'expanded' : ''}`}
        style={{ paddingLeft: indent }}
        data-toc-id={key}
        onClick={() => {
          if (hasChildren) {
            toggleNode(key);
          }
        }}
      >
        {hasChildren && (
          <span className="tree-toggle">
            <i className={`codicon codicon-chevron-${isExpanded ? 'down' : 'right'}`}></i>
          </span>
        )}
        {node.type === 'rule' && <span className={`tree-color color-${node.color || 'gray'}`} />}
        <span className="tree-name">{node.name}</span>
        {node.type === 'rule' &&
          node.ruleId &&
          summary?.validatingRuleIds?.includes(node.ruleId) && (
            <span className="validating-spinner" />
          )}
        <span className="hae-badge tree-count">{node.count}</span>
        {renderNodeActionButtons(node)}
      </div>
    );
  };

  const selectedTocRule = React.useMemo(
    () =>
      selectedRule
        ? tocItems
            .flatMap((item) => item.children ?? [])
            .find(
              (item) =>
                item.groupName === selectedRule.groupName && item.ruleName === selectedRule.ruleName
            )
        : undefined,
    [selectedRule, tocItems]
  );
  const selectedRuleId = selectedTocRule?.ruleId ?? processedTree[0]?.ruleId;
  const canRevalidateSelectedRule = !!selectedRuleId && validatableRuleIds.includes(selectedRuleId);
  const hasActiveFilters =
    searchTerm.trim().length > 0 || selectedSeverities.size !== SEVERITIES.length;
  const ruleCount = hasActiveFilters ? ruleFilteredResults : ruleTotalResults;
  const ruleCountLabel = hasActiveFilters || ruleCount > 0 ? `${ruleCount}` : '';

  if (isLanding) {
    return (
      <div className="databoard-view">
        <Brand logoUri={logoUri} />
        {renderHeader(false)}
        <div className="databoard-content">
          <LandingView isScanActive={isScanning} onScanWorkspace={scanWorkspace} />
        </div>
      </div>
    );
  }

  return (
    <div className="databoard-view">
      <Brand logoUri={logoUri} />
      {renderHeader(!!summary)}

      <div className="databoard-toolbar">
        <div className="search-box">
          <i className="codicon codicon-search search-icon"></i>
          <input
            type="text"
            className="search-input"
            placeholder={useRegex ? 'Search with regex...' : 'Search results...'}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button className="clear-btn" onClick={() => setSearchTerm('')}>
              ×
            </button>
          )}
          <button
            className={`regex-toggle ${useRegex ? 'active' : ''}`}
            onClick={() => setUseRegex(!useRegex)}
          >
            .*
          </button>
        </div>
        <div className="severity-filter">
          {['high', 'medium', 'low', 'none'].map((s) => (
            <button
              key={s}
              className={`severity-toggle severity-${s} ${selectedSeverities.has(s) ? 'active' : ''}`}
              onClick={() => toggleSeverity(s)}
            >
              <span className="severity-dot"></span>
              <span>{s.charAt(0).toUpperCase()}</span>
            </button>
          ))}
        </div>
        <div className="toolbar-actions">
          <button className="toolbar-btn" onClick={rescan} disabled={isScanning}>
            <i className="codicon codicon-refresh"></i>
          </button>
          <button className="toolbar-btn" onClick={clearResults} disabled={isScanning}>
            <i className="codicon codicon-trash"></i>
          </button>
        </div>
      </div>

      <div className="databoard-body">
        <div className="toc-sidebar" style={{ width: tocWidth, minWidth: tocWidth }}>
          <div className="toc-header">
            <span className="toc-title">OUTLINE</span>
          </div>
          <div className="toc-content">{tocItems.map((item) => renderTocItem(item, 0))}</div>
          <div className="toc-resize-handle" onMouseDown={handleResizeStart} />
        </div>

        <div className="databoard-panel">
          {selectedRule && (
            <div className="detail-header">
              <span className="detail-header-group">{selectedRule.groupName}</span>
              <span className="detail-header-sep">/</span>
              <span className="detail-header-title">{selectedRule.ruleName}</span>
              <span className="hae-badge">{ruleCountLabel}</span>
              <span className="btn-group" style={{ marginLeft: 'auto' }}>
                <button
                  className="copy-btn"
                  disabled={!canRevalidateSelectedRule}
                  onClick={() => {
                    if (!selectedRuleId) {
                      return;
                    }
                    vscode.postMessage({
                      command: 'revalidate',
                      ruleIds: [selectedRuleId],
                    });
                  }}
                >
                  <i className="codicon codicon-sparkle"></i>
                </button>
                <button
                  className="copy-btn"
                  onClick={(e) =>
                    copyMatches(
                      {
                        type: 'rule',
                        name: selectedRule.ruleName,
                        count: 0,
                        children: processedTree,
                      },
                      e
                    )
                  }
                >
                  <i className="codicon codicon-copy"></i>
                </button>
              </span>
            </div>
          )}
          <div className="databoard-content" ref={contentRef}>
            {!selectedRule ? (
              <div className="empty-state">
                <div className="empty-description">
                  Select an item from the outline to view results.
                </div>
              </div>
            ) : processedTree.length === 0 ? (
              <div className="empty-state">
                <div className="empty-title">No Results</div>
                <div className="empty-description">No results match your search criteria.</div>
              </div>
            ) : (
              <div
                className="databoard-tree"
                style={{
                  height: `${virtualizer.getTotalSize()}px`,
                  width: '100%',
                  position: 'relative',
                }}
              >
                {virtualizer.getVirtualItems().map((virtualRow) => {
                  const flatNode = visibleNodes[virtualRow.index];
                  return (
                    <div
                      key={flatNode.key}
                      data-index={virtualRow.index}
                      ref={virtualizer.measureElement}
                      style={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        width: '100%',
                        transform: `translateY(${virtualRow.start}px)`,
                      }}
                    >
                      {renderFlatNode(flatNode)}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {hoverTooltip && (
        <div className="hae-hover-tooltip" style={{ left: hoverTooltip.x, top: hoverTooltip.y }}>
          {hoverTooltip.text}
        </div>
      )}
    </div>
  );
};

export default DataboardView;
