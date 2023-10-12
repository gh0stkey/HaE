package burp.rule.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @author EvilChen
 */

public class RuleGroup {
    private Map<String, Object> fields;

    public RuleGroup(String groupName, List<Rule> rules) {
        List<Map<String, Object>> ruleList = new ArrayList<>();
        for (Rule rule : rules) {
            ruleList.add(rule.getFields());
        }

        fields = new LinkedHashMap<>();
        fields.put("group", groupName);
        fields.put("rule", ruleList);
    }

    public RuleGroup() {

    }

    public Map<String, Object> getFields() {
        return fields;
    }

    public void loadFields(Map<String, Object> fields) {
        this.fields = fields;
    }
}