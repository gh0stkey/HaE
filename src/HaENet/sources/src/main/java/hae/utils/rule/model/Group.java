package hae.utils.rule.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Group {
    private final Map<String, Object> fields;

    public Group(String groupName, List<RuleDefinition> rules) {
        List<Map<String, Object>> ruleList = rules.stream()
                .map(RuleDefinition::toYamlMap)
                .collect(Collectors.toList());

        fields = new LinkedHashMap<>();
        fields.put("group", groupName);
        fields.put("rule", ruleList);
    }

    public Map<String, Object> getFields() {
        return fields;
    }
}
