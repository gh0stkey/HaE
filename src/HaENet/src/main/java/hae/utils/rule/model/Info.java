package hae.utils.rule.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class Info {
    private Map<String, Object> fields;

    public Info(boolean loaded, String name, String f_regex, String s_regex, String format, String color, String scope, String engine, boolean sensitive) {
        fields = new LinkedHashMap<>();
        fields.put("name", name);
        fields.put("loaded", loaded);
        fields.put("f_regex", f_regex);
        fields.put("s_regex", s_regex);
        fields.put("format", format);
        fields.put("color", color);
        fields.put("scope", scope);
        fields.put("engine", engine);
        fields.put("sensitive", sensitive);
    }

    public Map<String, Object> getFields() {
        return fields;
    }

    public void loadFields(Map<String, Object> fields) {
        this.fields = fields;
    }
}