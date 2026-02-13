package hae.repository;

import java.util.Map;
import java.util.Set;

public interface RuleRepository {
    // 读
    Object[][] getRulesByGroup(String groupName);
    Set<String> getAllGroupNames();
    boolean containsGroup(String groupName);
    Map<String, Object[][]> getAll();

    // 写
    void setAll(Map<String, Object[][]> rules);
    void putGroup(String groupName, Object[][] rules);
    void removeGroup(String groupName);
    void renameGroup(String oldName, String newName);
    void updateRule(String groupName, int index, Object[] rule);
    void addRule(String groupName, Object[] rule);
    void removeRule(String groupName, int index);
}
