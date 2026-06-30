import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { ScanResult, ScanSummary, MatchSummary, FileHit, Severity } from '../types';
import { vscode } from '../utils/vscode';
import { COLOR_RANK } from '../utils/constants';
import { useDebouncedValue } from './useDebouncedValue';

export interface TreeNode {
  type: 'group' | 'rule' | 'file' | 'match';
  name: string;
  count: number;
  color?: string;
  children?: TreeNode[];
  result?: ScanResult;
  filePath?: string;
  severity?: Severity;
  ruleId?: string;
}

export interface FlatNode {
  node: TreeNode;
  key: string;
  depth: number;
  hasChildren: boolean;
  isExpanded: boolean;
}

export interface TocItem {
  id: string;
  name: string;
  count: number;
  type: 'group' | 'rule';
  color?: string;
  children?: TocItem[];
  groupName?: string;
  ruleName?: string;
  ruleId?: string;
}

interface UseDataboardProps {
  summary: ScanSummary | null;
  selectedRule: { groupName: string; ruleName: string } | null;
  workspaceRoots?: string[];
  isScanning?: boolean;
}

const normalizePath = (p: string): string => {
  return p.normalize('NFC').replace(/\\/g, '/').replace(/\/+/g, '/');
};

const getRelativePathFromWorkspace = (fullPath: string, workspaceRoots: string[]): string => {
  const normalized = normalizePath(fullPath);

  for (const root of workspaceRoots) {
    const normalizedRoot = normalizePath(root);
    const rootWithSlash = normalizedRoot.endsWith('/') ? normalizedRoot : normalizedRoot + '/';
    if (normalized.startsWith(rootWithSlash)) {
      const workspaceFolderName = normalizedRoot.split('/').filter(Boolean).pop() || '';
      const relativePart = normalized.substring(rootWithSlash.length);
      if (workspaceRoots.length > 1 && workspaceFolderName) {
        return workspaceFolderName + '/' + relativePart;
      }
      return relativePart;
    }
    if (normalized === normalizedRoot) {
      return normalized.split('/').pop() || normalized;
    }
  }

  return fullPath.split(/[/\\]/).pop() || fullPath;
};

export interface UseDataboardReturn {
  searchTerm: string;
  useRegex: boolean;
  processedTree: TreeNode[];
  visibleNodes: FlatNode[];
  selectedSeverities: Set<string>;
  toggleSeverity: (severity: string) => void;
  totalMatches: number;
  filteredResults: number;
  totalResults: number;
  loadingMatches: Set<string>;

  stats: {
    totalMatches: number;
    totalGroups: number;
  };

  tocItems: TocItem[];

  setSearchTerm: React.Dispatch<React.SetStateAction<string>>;
  setUseRegex: React.Dispatch<React.SetStateAction<boolean>>;
  toggleNode: (key: string) => void;
  openFile: (file: string, line: number, column?: number, match?: string) => void;
  rescan: () => void;
  scanWorkspace: () => void;
  clearResults: () => void;
  copyMatches: (node: TreeNode, e: React.MouseEvent) => void;
  revalidate: (node: TreeNode) => void;
  requestMatchFiles: (matchValues: string[]) => void;
}

export function useDataboard({
  summary,
  selectedRule,
  workspaceRoots = [],
  isScanning = false,
}: UseDataboardProps): UseDataboardReturn {
  const [searchTerm, setSearchTerm] = useState('');
  const [useRegex, setUseRegex] = useState(false);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [selectedSeverities, setSelectedSeverities] = useState<Set<string>>(
    new Set(['high', 'medium', 'low', 'none'])
  );

  const [matchSummaries, setMatchSummaries] = useState<MatchSummary[]>([]);
  const [totalMatches, setTotalMatches] = useState(0);
  const [filteredResults, setFilteredResults] = useState(0);
  const [totalResults, setTotalResults] = useState(0);
  const [fileCache, setFileCache] = useState<Map<string, FileHit[]>>(new Map());
  const [loadingMatches, setLoadingMatches] = useState<Set<string>>(new Set());
  const [staleMatches, setStaleMatches] = useState<Set<string>>(new Set());

  const queryVersionRef = useRef(0);
  const summariesRuleRef = useRef<{ groupName: string; ruleName: string } | null>(null);
  const fileCacheRef = useRef<Map<string, FileHit[]>>(new Map());

  useEffect(() => {
    fileCacheRef.current = fileCache;
  }, [fileCache]);

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      const message = event.data;
      if (message.type === 'ruleResults') {
        const payload = message.ruleResults;
        if (
          selectedRule &&
          payload.groupName === selectedRule.groupName &&
          payload.ruleName === selectedRule.ruleName
        ) {
          const versionChanged = payload.queryVersion !== queryVersionRef.current;
          queryVersionRef.current = payload.queryVersion;
          setMatchSummaries(payload.matches);
          setTotalMatches(payload.totalMatches);
          setFilteredResults(payload.filteredResults);
          setTotalResults(payload.totalResults);
          summariesRuleRef.current = { groupName: payload.groupName, ruleName: payload.ruleName };
          if (versionChanged) {
            const visibleMatches = new Set(payload.matches.map((match: MatchSummary) => match.match));
            const preservedCache = new Map<string, FileHit[]>();
            const nextStaleMatches = new Set<string>();

            for (const [matchValue, files] of fileCacheRef.current) {
              if (!visibleMatches.has(matchValue)) {
                continue;
              }
              preservedCache.set(matchValue, files);
              nextStaleMatches.add(matchValue);
            }

            setFileCache(preservedCache);
            setLoadingMatches(new Set());
            setStaleMatches(nextStaleMatches);
          }
        }
      } else if (message.type === 'matchFiles') {
        const payload = message.matchFiles;
        if (
          !selectedRule ||
          payload.groupName !== selectedRule.groupName ||
          payload.ruleName !== selectedRule.ruleName
        ) {
          return;
        }
        if (payload.queryVersion < queryVersionRef.current) return;
        if (payload.queryVersion > queryVersionRef.current) {
          queryVersionRef.current = payload.queryVersion;
        }
        setFileCache((prev) => {
          const next = new Map(prev);
          next.set(payload.matchValue, payload.files);
          return next;
        });
        setLoadingMatches((prev) => {
          const next = new Set(prev);
          next.delete(payload.matchValue);
          return next;
        });
        setStaleMatches((prev) => {
          const next = new Set(prev);
          next.delete(payload.matchValue);
          return next;
        });
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [selectedRule]);

  const debouncedSearchTerm = useDebouncedValue(searchTerm, 300);
  const lastQueryRef = useRef<string>('');

  const sendQuery = useCallback(
    (search?: string, regex?: boolean, severities?: Set<string>) => {
      if (!selectedRule) return;
      const s = search ?? debouncedSearchTerm;
      const r = regex ?? useRegex;
      const sev = severities ?? selectedSeverities;
      const sevArr: Severity[] = Array.from(sev) as Severity[];

      const key = `${selectedRule.groupName}|${selectedRule.ruleName}|${s}|${r}|${sevArr.sort().join(',')}`;
      if (key === lastQueryRef.current) return;
      lastQueryRef.current = key;

      vscode.postMessage({
        command: 'queryRuleResults',
        groupName: selectedRule.groupName,
        ruleName: selectedRule.ruleName,
        searchTerm: s || undefined,
        useRegex: r || undefined,
        severities: sevArr.length < 4 ? sevArr : undefined,
      });
    },
    [selectedRule, debouncedSearchTerm, useRegex, selectedSeverities]
  );

  useEffect(() => {
    if (selectedRule) {
      lastQueryRef.current = '';
      setExpandedNodes(new Set());
      sendQuery();
    }
  }, [selectedRule, sendQuery]);

  useEffect(() => {
    if (selectedRule) {
      sendQuery();
    }
  }, [debouncedSearchTerm, useRegex, selectedSeverities, sendQuery]);

  const severityFilterKey = Array.from(selectedSeverities).sort().join(',');

  useEffect(() => {
    setFileCache(new Map());
    setLoadingMatches(new Set());
    setStaleMatches(new Set());
  }, [selectedRule?.groupName, selectedRule?.ruleName, severityFilterKey]);

  const toggleSeverity = useCallback((severity: string) => {
    setSelectedSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(severity)) {
        next.delete(severity);
      } else {
        next.add(severity);
      }
      return next;
    });
  }, []);

  const requestMatchFiles = useCallback(
    (matchValues: string[]) => {
      if (!selectedRule) return;
      const toRequest = matchValues.filter(
        (v) => (!fileCache.has(v) || staleMatches.has(v)) && !loadingMatches.has(v)
      );
      if (toRequest.length === 0) return;
      setLoadingMatches((prev) => {
        const next = new Set(prev);
        for (const v of toRequest) next.add(v);
        return next;
      });
      vscode.postMessage({
        command: 'queryMatchFiles',
        groupName: selectedRule.groupName,
        ruleName: selectedRule.ruleName,
        matchValues: toRequest,
      });
    },
    [selectedRule, fileCache, loadingMatches, staleMatches]
  );

  const tree = useMemo(() => {
    if (matchSummaries.length === 0 || !selectedRule) return [];
    if (
      !summariesRuleRef.current ||
      summariesRuleRef.current.groupName !== selectedRule.groupName ||
      summariesRuleRef.current.ruleName !== selectedRule.ruleName
    )
      return [];

    return matchSummaries.map((s): TreeNode => {
      const cached = fileCache.get(s.match);
      const children = cached
        ? cached.map(
            (f): TreeNode => ({
              type: 'file',
              name: getRelativePathFromWorkspace(f.file, workspaceRoots),
              filePath: f.file,
              count: 1,
              color: s.color,
              result: {
                file: f.file,
                line: f.line,
                column: f.column,
                match: s.match,
                ruleId: s.ruleId,
                ruleName: selectedRule.ruleName,
                severity: f.severity,
                color: s.color,
              },
            })
          )
        : undefined;

      return {
        type: 'match',
        name: s.match,
        count: s.count,
        severity: s.severity,
        color: s.color,
        ruleId: s.ruleId,
        children,
      };
    });
  }, [matchSummaries, fileCache, selectedRule, workspaceRoots]);

  const visibleNodes = useMemo(() => {
    const result: FlatNode[] = [];
    const flatten = (nodes: TreeNode[], parentKey: string, depth: number) => {
      for (const node of nodes) {
        let key: string;
        if (node.type === 'file' && node.result) {
          key = `${parentKey}/${node.type}:${node.result.file}:${node.result.line}:${node.result.column}`;
        } else if (node.type === 'match') {
          key = `${parentKey}/${node.type}:${node.name}`;
        } else if (parentKey) {
          key = `${parentKey}/${node.type}:${node.filePath || node.name}`;
        } else {
          key = `${node.type}:${node.filePath || node.name}`;
        }

        const hasChildren =
          node.type === 'match' ? node.count > 0 : !!(node.children && node.children.length > 0);
        const isExpanded = expandedNodes.has(key);

        result.push({ node, key, depth, hasChildren, isExpanded });

        if (isExpanded) {
          if (node.children && node.children.length > 0) {
            flatten(node.children, key, depth + 1);
          } else if (node.type === 'match' && node.children === undefined) {
            const loadingNode: TreeNode = { type: 'file', name: 'Loading...', count: 0 };
            result.push({
              node: loadingNode,
              key: `${key}/__loading`,
              depth: depth + 1,
              hasChildren: false,
              isExpanded: false,
            });
          }
        }
      }
    };
    flatten(tree, '', 0);
    return result;
  }, [tree, expandedNodes]);

  useEffect(() => {
    const needFiles: string[] = [];
    for (const flat of visibleNodes) {
      if (
        flat.node.type === 'match' &&
        flat.isExpanded &&
        (flat.node.children === undefined || staleMatches.has(flat.node.name)) &&
        !loadingMatches.has(flat.node.name)
      ) {
        needFiles.push(flat.node.name);
      }
    }
    if (needFiles.length > 0) {
      requestMatchFiles(needFiles);
    }
  }, [visibleNodes, loadingMatches, staleMatches, requestMatchFiles]);

  const stats = useMemo(() => {
    if (!summary) {
      return { totalMatches: 0, totalGroups: 0 };
    }
    let total = 0;
    for (const group of summary.groups) {
      for (const rule of group.rules) {
        total += rule.count;
      }
    }
    return {
      totalMatches: total,
      totalGroups: summary.groups.length,
    };
  }, [summary]);

  const tocItems = useMemo((): TocItem[] => {
    if (!summary) return [];

    return summary.groups
      .map((group) => {
        const ruleItems: TocItem[] = group.rules
          .map((rule) => ({
            id: `rule:${group.name}/${rule.name}`,
            name: rule.name,
            count: rule.count,
            type: 'rule' as const,
            color: rule.color,
            groupName: group.name,
            ruleName: rule.name,
            ruleId: rule.ruleId,
          }))
          .sort((a, b) => {
            const aRank = COLOR_RANK[a.color || 'none'] ?? 9;
            const bRank = COLOR_RANK[b.color || 'none'] ?? 9;
            if (aRank !== bRank) return aRank - bRank;
            return b.count - a.count;
          });

        return {
          id: `group:${group.name}`,
          name: group.name,
          count: group.rules.reduce((sum, r) => sum + r.count, 0),
          type: 'group' as const,
          children: ruleItems,
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [summary]);

  const toggleNode = useCallback(
    (key: string) => {
      setExpandedNodes((prev) => {
        const next = new Set(prev);
        if (next.has(key)) {
          next.delete(key);
        } else {
          next.add(key);
          const matchPrefix = '/match:';
          const idx = key.lastIndexOf(matchPrefix);
          if (idx !== -1) {
            const matchValue = key.substring(idx + matchPrefix.length);
            if (
              (!fileCache.has(matchValue) || staleMatches.has(matchValue)) &&
              !loadingMatches.has(matchValue)
            ) {
              requestMatchFiles([matchValue]);
            }
          }
        }
        return next;
      });
    },
    [fileCache, loadingMatches, staleMatches, requestMatchFiles]
  );

  const openFile = useCallback((file: string, line: number, column?: number, match?: string) => {
    vscode.openFile(file, line, column ?? 0, match ?? '');
  }, []);

  const rescan = useCallback(() => {
    if (isScanning) {
      return;
    }
    vscode.postMessage({ command: 'rescan' });
  }, [isScanning]);

  const scanWorkspace = useCallback(() => {
    if (isScanning) {
      return;
    }
    vscode.postMessage({ command: 'scanWorkspace' });
  }, [isScanning]);

  const clearResults = useCallback(() => {
    vscode.postMessage({ command: 'clearResults' });
  }, []);

  const collectMatches = useCallback((node: TreeNode): string[] => {
    const matches: string[] = [];

    if (node.type === 'match') {
      matches.push(node.name);
    } else if (node.children) {
      node.children.forEach((child) => {
        matches.push(...collectMatches(child));
      });
    }

    return [...new Set(matches)];
  }, []);

  const copyMatches = useCallback(
    (node: TreeNode, e: React.MouseEvent) => {
      e.stopPropagation();
      const matches = collectMatches(node);
      const text = matches.join('\n');
      void vscode.copyTextWithInfo(
        text,
        `Copied ${matches.length} unique match${matches.length > 1 ? 'es' : ''} to clipboard`
      );
    },
    [collectMatches]
  );

  const collectRuleIds = useCallback((node: TreeNode): string[] => {
    if (node.ruleId) {
      return [node.ruleId];
    }
    if (node.children) {
      const ids = new Set<string>();
      for (const child of node.children) {
        for (const id of collectRuleIds(child)) {
          ids.add(id);
        }
      }
      return Array.from(ids);
    }
    return [];
  }, []);

  const revalidate = useCallback(
    (node: TreeNode) => {
      const ruleIds = collectRuleIds(node);
      if (ruleIds.length === 0) {
        return;
      }
      const matchValues = node.type === 'match' ? [node.name] : undefined;
      vscode.postMessage({ command: 'revalidate', ruleIds, matchValues });
    },
    [collectRuleIds]
  );

  return {
    searchTerm,
    useRegex,
    processedTree: tree,
    visibleNodes,
    selectedSeverities,
    toggleSeverity,
    totalMatches,
    filteredResults,
    totalResults,
    loadingMatches,
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
    requestMatchFiles,
  };
}
