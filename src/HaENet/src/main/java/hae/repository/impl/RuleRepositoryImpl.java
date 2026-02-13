package hae.repository.impl;

import hae.repository.RuleRepository;

import java.util.*;

public class RuleRepositoryImpl implements RuleRepository {
    private final Map<String, Object[][]> rules;

    public RuleRepositoryImpl(Map<String, Object[][]> initialRules) {
        this.rules = new HashMap<>(initialRules);
    }

    @Override
    public synchronized Object[][] getRulesByGroup(String groupName) {
        return rules.get(groupName);
    }

    @Override
    public synchronized Set<String> getAllGroupNames() {
        return new HashSet<>(rules.keySet());
    }

    @Override
    public synchronized boolean containsGroup(String groupName) {
        return rules.containsKey(groupName);
    }

    @Override
    public synchronized Map<String, Object[][]> getAll() {
        return new HashMap<>(rules);
    }

    @Override
    public synchronized void setAll(Map<String, Object[][]> newRules) {
        rules.clear();
        rules.putAll(newRules);
    }

    @Override
    public synchronized void putGroup(String groupName, Object[][] groupRules) {
        rules.put(groupName, groupRules);
    }

    @Override
    public synchronized void removeGroup(String groupName) {
        rules.remove(groupName);
    }

    @Override
    public synchronized void renameGroup(String oldName, String newName) {
        rules.put(newName, rules.remove(oldName));
    }

    @Override
    public synchronized void updateRule(String groupName, int index, Object[] rule) {
        rules.get(groupName)[index] = rule;
    }

    @Override
    public synchronized void addRule(String groupName, Object[] rule) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(rules.get(groupName)));
        x.add(rule);
        rules.put(groupName, x.toArray(new Object[x.size()][]));
    }

    @Override
    public synchronized void removeRule(String groupName, int index) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(rules.get(groupName)));
        x.remove(index);
        rules.put(groupName, x.toArray(new Object[x.size()][]));
    }
}
