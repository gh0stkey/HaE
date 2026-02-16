package hae.repository;

import hae.utils.rule.model.RuleDefinition;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface RuleRepository {
    // 读
    List<RuleDefinition> getRulesByGroup(String groupName);
    Set<String> getAllGroupNames();
    boolean containsGroup(String groupName);
    Map<String, List<RuleDefinition>> getAll();

    // 写
    void setAll(Map<String, List<RuleDefinition>> rules);
    void putGroup(String groupName, List<RuleDefinition> rules);
    void removeGroup(String groupName);
    void renameGroup(String oldName, String newName);
    void updateRule(String groupName, int index, RuleDefinition rule);
    void addRule(String groupName, RuleDefinition rule);
    void removeRule(String groupName, int index);
}
