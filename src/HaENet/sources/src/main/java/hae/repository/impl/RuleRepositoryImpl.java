package hae.repository.impl;

import hae.repository.RuleRepository;
import hae.utils.rule.model.RuleDefinition;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RuleRepositoryImpl implements RuleRepository {
    private final ConcurrentHashMap<String, List<RuleDefinition>> rules;

    public RuleRepositoryImpl(Map<String, List<RuleDefinition>> initialRules) {
        this.rules = new ConcurrentHashMap<>(initialRules);
    }

    @Override
    public List<RuleDefinition> getRulesByGroup(String groupName) {
        List<RuleDefinition> group = rules.get(groupName);
        return group != null ? new ArrayList<>(group) : null;
    }

    @Override
    public Set<String> getAllGroupNames() {
        return new HashSet<>(rules.keySet());
    }

    @Override
    public boolean containsGroup(String groupName) {
        return rules.containsKey(groupName);
    }

    @Override
    public Map<String, List<RuleDefinition>> getAll() {
        return new HashMap<>(rules);
    }

    @Override
    public synchronized void setAll(Map<String, List<RuleDefinition>> newRules) {
        rules.clear();
        rules.putAll(newRules);
    }

    @Override
    public void putGroup(String groupName, List<RuleDefinition> groupRules) {
        rules.put(groupName, new ArrayList<>(groupRules));
    }

    @Override
    public void removeGroup(String groupName) {
        rules.remove(groupName);
    }

    @Override
    public synchronized void renameGroup(String oldName, String newName) {
        List<RuleDefinition> data = rules.remove(oldName);
        if (data != null) {
            rules.put(newName, data);
        }
    }

    @Override
    public synchronized void updateRule(String groupName, int index, RuleDefinition rule) {
        List<RuleDefinition> group = rules.get(groupName);
        if (group != null && index >= 0 && index < group.size()) {
            group.set(index, rule);
        }
    }

    @Override
    public synchronized void addRule(String groupName, RuleDefinition rule) {
        List<RuleDefinition> group = rules.get(groupName);
        if (group == null) {
            return;
        }
        group.add(rule);
    }

    @Override
    public synchronized void removeRule(String groupName, int index) {
        List<RuleDefinition> group = rules.get(groupName);
        if (group == null || index < 0 || index >= group.size()) {
            return;
        }
        group.remove(index);
    }
}
