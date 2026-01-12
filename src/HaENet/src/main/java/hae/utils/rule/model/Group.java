package hae.utils.rule.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Group {
    private Map<String, Object> fields;

    public Group(String groupName, List<Info> rules) {
        List<Map<String, Object>> ruleList = new ArrayList<>();
        for (Info rule : rules) {
            ruleList.add(rule.getFields());
        }

        fields = new LinkedHashMap<>();
        fields.put("group", groupName);
        fields.put("rule", ruleList);
    }

    public Map<String, Object> getFields() {
        return fields;
    }

    public void loadFields(Map<String, Object> fields) {
        this.fields = fields;
    }
}
