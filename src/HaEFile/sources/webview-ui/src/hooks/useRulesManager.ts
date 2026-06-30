import { useMemo, useCallback, useReducer } from 'react';
import { ScanRule, RuleColor, ValidatorConfig } from '../types';
import { vscode } from '../utils/vscode';

type EditingRule = Partial<ScanRule> & {
  isNew?: boolean;
  validatorCommand?: string;
  validatorTimeout?: number;
  validatorBulk?: number;
};

interface UseRulesManagerProps {
  rules: ScanRule[];
}

interface RegexValidation {
  isValid: boolean;
  error?: string;
}

interface RulesManagerState {
  editingRule: EditingRule | null;
  expandedGroups: Set<string>;
  searchTerm: string;
  colorPickerRuleId: string | null;
  editingGroupName: string | null;
  editingGroupNewName: string;
}

type RulesManagerAction =
  | { type: 'SET_EDITING_RULE'; payload: EditingRule | null }
  | { type: 'TOGGLE_GROUP'; payload: string }
  | { type: 'SET_SEARCH_TERM'; payload: string }
  | { type: 'SET_COLOR_PICKER_RULE_ID'; payload: string | null }
  | { type: 'SET_EDITING_GROUP_NAME'; payload: string | null }
  | { type: 'SET_EDITING_GROUP_NEW_NAME'; payload: string }
  | { type: 'START_EDIT'; payload: ScanRule }
  | { type: 'START_CREATE'; payload?: string }
  | { type: 'CANCEL_EDIT' }
  | { type: 'CANCEL_EDIT_GROUP' }
  | { type: 'EXPAND_ALL'; payload: string[] };

function rulesManagerReducer(
  state: RulesManagerState,
  action: RulesManagerAction
): RulesManagerState {
  switch (action.type) {
    case 'SET_EDITING_RULE':
      return { ...state, editingRule: action.payload };

    case 'TOGGLE_GROUP': {
      const next = new Set(state.expandedGroups);
      if (next.has(action.payload)) {
        next.delete(action.payload);
      } else {
        next.add(action.payload);
      }
      return { ...state, expandedGroups: next };
    }

    case 'SET_SEARCH_TERM':
      return { ...state, searchTerm: action.payload };

    case 'SET_COLOR_PICKER_RULE_ID':
      return { ...state, colorPickerRuleId: action.payload };

    case 'SET_EDITING_GROUP_NAME':
      return { ...state, editingGroupName: action.payload };

    case 'SET_EDITING_GROUP_NEW_NAME':
      return { ...state, editingGroupNewName: action.payload };

    case 'START_EDIT':
      return {
        ...state,
        editingRule: {
          ...action.payload,
          validatorCommand: action.payload.validator?.command || '',
          validatorTimeout: action.payload.validator?.timeout || 5000,
          validatorBulk: action.payload.validator?.bulk || 500,
        },
      };

    case 'START_CREATE':
      return {
        ...state,
        editingRule: {
          isNew: true,
          name: '',
          group: action.payload || '',
          regex: '',
          color: 'red',
          loaded: true,
          sensitive: false,
          validatorCommand: '',
          validatorTimeout: 5000,
          validatorBulk: 500,
        },
      };

    case 'CANCEL_EDIT':
      return {
        ...state,
        editingRule: null,
      };

    case 'CANCEL_EDIT_GROUP':
      return {
        ...state,
        editingGroupName: null,
        editingGroupNewName: '',
      };

    case 'EXPAND_ALL':
      return {
        ...state,
        expandedGroups: new Set(action.payload),
      };

    default:
      return state;
  }
}

interface UseRulesManagerReturn {
  editingRule: EditingRule | null;
  expandedGroups: Set<string>;
  searchTerm: string;
  colorPickerRuleId: string | null;
  editingGroupName: string | null;
  editingGroupNewName: string;

  existingGroups: string[];
  filteredGroups: Record<string, ScanRule[]>;
  regexValidation: RegexValidation;

  setEditingRule: React.Dispatch<React.SetStateAction<EditingRule | null>>;
  setSearchTerm: React.Dispatch<React.SetStateAction<string>>;
  setEditingGroupNewName: React.Dispatch<React.SetStateAction<string>>;

  toggleGroup: (group: string) => void;
  toggleGroupEnabled: (groupName: string, groupRules: ScanRule[]) => void;
  startEdit: (rule: ScanRule) => void;
  startCreate: () => void;
  startCreateInGroup: (groupName: string) => void;
  cancelEdit: () => void;
  toggleRuleEnabled: (rule: ScanRule) => void;
  changeRuleColor: (rule: ScanRule, newColor: RuleColor) => void;
  toggleColorPicker: (ruleId: string, e: React.MouseEvent) => void;
  saveRule: () => void;
  deleteRule: (id: string) => void;
  deleteGroup: (groupName: string) => void;
  startEditGroup: (groupName: string) => void;
  cancelEditGroup: () => void;
  saveEditGroup: () => void;
  importRules: () => void;
  exportRules: () => void;
  expandAll: () => void;
}

export function useRulesManager({ rules }: UseRulesManagerProps): UseRulesManagerReturn {
  const [state, dispatch] = useReducer(rulesManagerReducer, {
    editingRule: null,
    expandedGroups: new Set<string>(),
    searchTerm: '',
    colorPickerRuleId: null,
    editingGroupName: null,
    editingGroupNewName: '',
  });

  const regexValidation = useMemo<RegexValidation>(() => {
    if (!state.editingRule?.regex) {
      return { isValid: true };
    }
    try {
      const flags = state.editingRule.sensitive ? 'g' : 'gi';
      new RegExp(state.editingRule.regex, flags);
      return { isValid: true };
    } catch (e) {
      return {
        isValid: false,
        error: e instanceof Error ? e.message : 'Invalid regex',
      };
    }
  }, [state.editingRule?.regex, state.editingRule?.sensitive]);

  const groupedRules = useMemo(() => {
    const grouped: Record<string, ScanRule[]> = {};
    rules.forEach((rule) => {
      const group = rule.group || 'Default';
      if (!grouped[group]) {
        grouped[group] = [];
      }
      grouped[group].push(rule);
    });
    Object.keys(grouped).forEach((group) => {
      grouped[group].sort((a, b) => a.name.localeCompare(b.name));
    });
    return grouped;
  }, [rules]);

  const existingGroups = useMemo(() => {
    return Object.keys(groupedRules).sort();
  }, [groupedRules]);

  const filteredGroups = useMemo(() => {
    if (!state.searchTerm) return groupedRules;

    const term = state.searchTerm.toLowerCase();
    const filtered: Record<string, ScanRule[]> = {};

    Object.entries(groupedRules).forEach(([group, groupRules]) => {
      const matchingRules = groupRules.filter(
        (rule) =>
          rule.name.toLowerCase().includes(term) ||
          rule.regex.toLowerCase().includes(term) ||
          group.toLowerCase().includes(term)
      );

      if (matchingRules.length > 0) {
        filtered[group] = matchingRules;
      }
    });

    return filtered;
  }, [groupedRules, state.searchTerm]);

  const toggleGroup = useCallback((group: string) => {
    dispatch({ type: 'TOGGLE_GROUP', payload: group });
  }, []);

  const toggleGroupEnabled = useCallback((_groupName: string, groupRules: ScanRule[]) => {
    const allEnabled = groupRules.every((rule) => rule.loaded);
    const newState = !allEnabled;

    groupRules.forEach((rule) => {
      if (rule.loaded !== newState) {
        vscode.postMessage({
          command: 'updateRule',
          rule: { ...rule, loaded: newState },
        });
      }
    });
  }, []);

  const startEdit = useCallback((rule: ScanRule) => {
    dispatch({ type: 'START_EDIT', payload: rule });
  }, []);

  const startCreate = useCallback(() => {
    dispatch({ type: 'START_CREATE' });
  }, []);

  const startCreateInGroup = useCallback((groupName: string) => {
    dispatch({ type: 'START_CREATE', payload: groupName });
  }, []);

  const cancelEdit = useCallback(() => {
    dispatch({ type: 'CANCEL_EDIT' });
  }, []);

  const toggleRuleEnabled = useCallback((rule: ScanRule) => {
    const updatedRule = { ...rule, loaded: !rule.loaded };
    vscode.postMessage({
      command: 'updateRule',
      rule: updatedRule,
    });
  }, []);

  const changeRuleColor = useCallback((rule: ScanRule, newColor: RuleColor) => {
    const updatedRule = { ...rule, color: newColor };
    vscode.postMessage({
      command: 'updateRule',
      rule: updatedRule,
    });
    dispatch({ type: 'SET_COLOR_PICKER_RULE_ID', payload: null });
  }, []);

  const toggleColorPicker = useCallback(
    (ruleId: string, e: React.MouseEvent) => {
      e.stopPropagation();
      dispatch({
        type: 'SET_COLOR_PICKER_RULE_ID',
        payload: state.colorPickerRuleId === ruleId ? null : ruleId,
      });
    },
    [state.colorPickerRuleId]
  );

  const saveRule = useCallback(() => {
    const editingRule = state.editingRule;
    if (!editingRule) return;

    if (!editingRule.name || !editingRule.regex) {
      return;
    }

    try {
      const flags = editingRule.sensitive ? 'g' : 'gi';
      new RegExp(editingRule.regex, flags);
    } catch {
      return;
    }

    const finalGroup = editingRule.group || 'Default';

    const validator: ValidatorConfig | undefined = editingRule.validatorCommand?.trim()
      ? {
          command: editingRule.validatorCommand.trim(),
          timeout: editingRule.validatorTimeout || 5000,
          bulk: editingRule.validatorBulk || 500,
        }
      : undefined;

    const ruleToSave: ScanRule = {
      id: editingRule.isNew ? 'new_' : editingRule.id!,
      name: editingRule.name!,
      group: finalGroup,
      regex: editingRule.regex!,
      color: editingRule.color || 'green',
      loaded: editingRule.loaded ?? true,
      sensitive: editingRule.sensitive ?? false,
      validator: validator,
    };

    vscode.postMessage({
      command: editingRule.isNew ? 'addRule' : 'updateRule',
      rule: ruleToSave,
    });

    dispatch({ type: 'CANCEL_EDIT' });
  }, [state.editingRule]);

  const deleteRule = useCallback((id: string) => {
    vscode.postMessage({
      command: 'confirmDeleteRule',
      id,
    });
  }, []);

  const deleteGroup = useCallback((groupName: string) => {
    vscode.postMessage({
      command: 'deleteGroup',
      groupName,
    });
  }, []);

  const startEditGroup = useCallback((groupName: string) => {
    dispatch({ type: 'SET_EDITING_GROUP_NAME', payload: groupName });
    dispatch({ type: 'SET_EDITING_GROUP_NEW_NAME', payload: groupName });
  }, []);

  const cancelEditGroup = useCallback(() => {
    dispatch({ type: 'CANCEL_EDIT_GROUP' });
  }, []);

  const saveEditGroup = useCallback(() => {
    if (!state.editingGroupName || !state.editingGroupNewName.trim()) {
      dispatch({ type: 'CANCEL_EDIT_GROUP' });
      return;
    }
    if (state.editingGroupNewName.trim() === state.editingGroupName) {
      dispatch({ type: 'CANCEL_EDIT_GROUP' });
      return;
    }
    vscode.postMessage({
      command: 'renameGroup',
      oldName: state.editingGroupName,
      newName: state.editingGroupNewName.trim(),
    });
    dispatch({ type: 'CANCEL_EDIT_GROUP' });
  }, [state.editingGroupName, state.editingGroupNewName]);

  const importRules = useCallback(() => {
    vscode.postMessage({ command: 'importRules' });
  }, []);

  const exportRules = useCallback(() => {
    vscode.postMessage({ command: 'exportRules' });
  }, []);

  const setEditingRule = useCallback(
    (value: React.SetStateAction<EditingRule | null>) => {
      const newValue = typeof value === 'function' ? value(state.editingRule) : value;
      dispatch({ type: 'SET_EDITING_RULE', payload: newValue });
    },
    [state.editingRule]
  );

  const setSearchTerm = useCallback(
    (value: React.SetStateAction<string>) => {
      const newValue = typeof value === 'function' ? value(state.searchTerm) : value;
      dispatch({ type: 'SET_SEARCH_TERM', payload: newValue });
    },
    [state.searchTerm]
  );

  const setEditingGroupNewName = useCallback(
    (value: React.SetStateAction<string>) => {
      const newValue = typeof value === 'function' ? value(state.editingGroupNewName) : value;
      dispatch({ type: 'SET_EDITING_GROUP_NEW_NAME', payload: newValue });
    },
    [state.editingGroupNewName]
  );

  const expandAll = useCallback(() => {
    const allGroups = Object.keys(filteredGroups);
    dispatch({ type: 'EXPAND_ALL', payload: allGroups });
  }, [filteredGroups]);

  return {
    editingRule: state.editingRule,
    expandedGroups: state.expandedGroups,
    searchTerm: state.searchTerm,
    colorPickerRuleId: state.colorPickerRuleId,
    editingGroupName: state.editingGroupName,
    editingGroupNewName: state.editingGroupNewName,
    existingGroups,
    filteredGroups,
    regexValidation,
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
  };
}
