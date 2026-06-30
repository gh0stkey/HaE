import React, { useState, useMemo, useCallback } from 'react';
import { ActiveFilePayload, ScanResult } from '../types';
import { vscode } from '../utils/vscode';
import { COLOR_RANK } from '../utils/constants';
import { useResize } from '../hooks';
import '../styles/detailHeader.css';
import './FileInspectorPanel.css';

interface DedupedMatch {
  match: string;
  results: ScanResult[];
}

interface FileInspectorPanelProps {
  activeFileData: ActiveFilePayload | null;
}

const FileInspectorPanel: React.FC<FileInspectorPanelProps> = ({ activeFileData }) => {
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [useRegex, setUseRegex] = useState(false);
  const [expandedMatches, setExpandedMatches] = useState<Set<string>>(new Set());
  const { width: sidebarWidth, handleResizeStart } = useResize({ initialWidth: 240 });

  const sortedGroups = useMemo(() => {
    if (!activeFileData) return [];
    return [...activeFileData.groups].sort((a, b) => {
      const aRank = COLOR_RANK[a.color || 'none'] ?? 9;
      const bRank = COLOR_RANK[b.color || 'none'] ?? 9;
      if (aRank !== bRank) return aRank - bRank;
      return b.results.length - a.results.length;
    });
  }, [activeFileData]);

  const selectedGroup = useMemo(() => {
    if (!selectedRule) return null;
    return sortedGroups.find((g) => `${g.groupName}::${g.ruleName}` === selectedRule) ?? null;
  }, [selectedRule, sortedGroups]);

  const dedupedMatches = useMemo((): DedupedMatch[] => {
    if (!selectedGroup) return [];
    const map = new Map<string, ScanResult[]>();
    for (const r of selectedGroup.results) {
      const existing = map.get(r.match);
      if (existing) {
        existing.push(r);
      } else {
        map.set(r.match, [r]);
      }
    }

    let entries = Array.from(map.entries());

    if (searchTerm) {
      if (useRegex) {
        try {
          const re = new RegExp(searchTerm, 'i');
          entries = entries.filter(([match]) => re.test(match));
        } catch {
          const lower = searchTerm.toLowerCase();
          entries = entries.filter(([match]) => match.toLowerCase().includes(lower));
        }
      } else {
        const lower = searchTerm.toLowerCase();
        entries = entries.filter(([match]) => match.toLowerCase().includes(lower));
      }
    }

    return entries
      .map(([match, results]) => ({ match, results }))
      .sort((a, b) => b.results.length - a.results.length);
  }, [selectedGroup, searchTerm, useRegex]);

  const filteredTotalCount = useMemo(
    () => dedupedMatches.reduce((sum, d) => sum + d.results.length, 0),
    [dedupedMatches]
  );

  const toggleMatch = useCallback((match: string) => {
    setExpandedMatches((prev) => {
      const next = new Set(prev);
      if (next.has(match)) {
        next.delete(match);
      } else {
        next.add(match);
      }
      return next;
    });
  }, []);

  const openFile = (file: string, line: number, column: number, match: string) => {
    vscode.openFile(file, line, column, match);
  };

  const copyText = (text: string) => {
    void vscode.copyTextWithInfo(text);
  };

  if (!activeFileData) {
    return (
      <div className="fip">
        <div className="fip-empty">
          <span>No open file</span>
        </div>
      </div>
    );
  }

  if (activeFileData.totalCount === 0) {
    return (
      <div className="fip">
        <div className="fip-empty">
          <span>No matches in this file</span>
        </div>
      </div>
    );
  }

  return (
    <div className="fip">
      <div className="fip-sidebar" style={{ width: sidebarWidth, minWidth: sidebarWidth }}>
        <div className="fip-sidebar-header">
          <span className="fip-header-title">INSPECTOR</span>
        </div>
        <div className="fip-rule-list">
          {sortedGroups.map((group) => {
            const ruleKey = `${group.groupName}::${group.ruleName}`;
            const isSelected = selectedRule === ruleKey;
            return (
              <div
                key={ruleKey}
                className={`fip-rule ${isSelected ? 'fip-rule--selected' : ''}`}
                onClick={() => setSelectedRule(isSelected ? null : ruleKey)}
              >
                <span className={`hae-color-dot color-${group.color || 'gray'}`} />
                <span className="fip-rule-name">{group.ruleName}</span>
                <span className="hae-badge">{group.results.length}</span>
              </div>
            );
          })}
        </div>
        <div className="fip-resize-handle" onMouseDown={handleResizeStart} />
      </div>
      <div className="fip-detail">
        {selectedGroup ? (
          <>
            <div className="detail-header">
              <span className="detail-header-group">{selectedGroup.groupName}</span>
              <span className="detail-header-sep">/</span>
              <span className="detail-header-title">{selectedGroup.ruleName}</span>
              <span className="hae-badge">{filteredTotalCount}</span>
              <button
                className="fip-action-btn"
                onClick={() => copyText(dedupedMatches.map((d) => d.match).join('\n'))}
              >
                <i className="codicon codicon-copy"></i>
              </button>
            </div>
            <div className="fip-search-bar">
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
            </div>
            <div className="fip-detail-list">
              {dedupedMatches.map((deduped) => {
                const isExpanded = expandedMatches.has(deduped.match);
                return (
                  <div key={deduped.match} className="fip-dedup-group">
                    <div
                      className={`fip-detail-row fip-dedup-header ${isExpanded ? 'expanded' : ''}`}
                      onClick={() => toggleMatch(deduped.match)}
                    >
                      <span className="fip-toggle">
                        <i
                          className={`codicon codicon-chevron-${isExpanded ? 'down' : 'right'}`}
                        ></i>
                      </span>
                      <span className="fip-detail-match">{deduped.match}</span>
                      <span className="hae-badge">{deduped.results.length}</span>
                      <button
                        className="fip-action-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          copyText(deduped.match);
                        }}
                      >
                        <i className="codicon codicon-copy"></i>
                      </button>
                    </div>
                    {isExpanded && (
                      <div className="fip-line-list">
                        {deduped.results.map((result, idx) => (
                          <div
                            key={idx}
                            className="fip-line-row"
                            onClick={() =>
                              openFile(result.file, result.line, result.column, result.match)
                            }
                          >
                            <span className="fip-line-label">
                              Line {result.line}:{result.column + 1}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        ) : (
          <div className="fip-detail-placeholder">
            <span>Select a rule to view matches</span>
          </div>
        )}
      </div>
    </div>
  );
};

export default FileInspectorPanel;
