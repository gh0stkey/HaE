package burp.rule.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author EvilChen
 */

public class Rule {
    private Map<String, Object> fields;

    public Rule(boolean loaded, String name, String regex, String color, String scope, String engine, boolean sensitive) {
        fields = new LinkedHashMap<>();
        fields.put("name", name);
        fields.put("loaded", loaded);
        fields.put("regex", regex);
        fields.put("color", color);
        fields.put("scope", scope);
        fields.put("engine", engine);
        fields.put("sensitive", sensitive);
    }

    public Rule() {

    }

    public Map<String, Object> getFields() {
        return fields;
    }

    public void loadFields(Map<String, Object> fields) {
        this.fields = fields;
    }
}