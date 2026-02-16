package hae.utils.rule.model;

import java.util.LinkedHashMap;
import java.util.Map;

public class RuleDefinition {
    private boolean loaded;
    private String name;
    private String firstRegex;
    private String secondRegex;
    private String format;
    private String color;
    private String scope;
    private String engine;
    private boolean sensitive;

    public RuleDefinition(boolean loaded, String name, String firstRegex, String secondRegex,
                          String format, String color, String scope, String engine, boolean sensitive) {
        this.loaded = loaded;
        this.name = name;
        this.firstRegex = firstRegex;
        this.secondRegex = secondRegex;
        this.format = format;
        this.color = color;
        this.scope = scope;
        this.engine = engine;
        this.sensitive = sensitive;
    }

    // ---- Getters ----

    public boolean isLoaded() {
        return loaded;
    }

    public String getName() {
        return name;
    }

    public String getFirstRegex() {
        return firstRegex;
    }

    public String getSecondRegex() {
        return secondRegex;
    }

    public String getFormat() {
        return format;
    }

    public String getColor() {
        return color;
    }

    public String getScope() {
        return scope;
    }

    public String getEngine() {
        return engine;
    }

    public boolean isSensitive() {
        return sensitive;
    }

    // ---- Setters ----

    public void setLoaded(boolean loaded) {
        this.loaded = loaded;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setFirstRegex(String firstRegex) {
        this.firstRegex = firstRegex;
    }

    public void setSecondRegex(String secondRegex) {
        this.secondRegex = secondRegex;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public void setEngine(String engine) {
        this.engine = engine;
    }

    public void setSensitive(boolean sensitive) {
        this.sensitive = sensitive;
    }

    public static RuleDefinition fromObjectArray(Object[] objects) {
        return new RuleDefinition(
                (boolean) objects[0],
                (String) objects[1],
                (String) objects[2],
                (String) objects[3],
                (String) objects[4],
                (String) objects[5],
                (String) objects[6],
                (String) objects[7],
                (boolean) objects[8]
        );
    }

    public Object[] toObjectArray() {
        return new Object[]{loaded, name, firstRegex, secondRegex, format, color, scope, engine, sensitive};
    }

    public Map<String, Object> toYamlMap() {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("name", name);
        fields.put("loaded", loaded);
        fields.put("f_regex", firstRegex);
        fields.put("s_regex", secondRegex);
        fields.put("format", format);
        fields.put("color", color);
        fields.put("scope", scope);
        fields.put("engine", engine);
        fields.put("sensitive", sensitive);
        return fields;
    }

    public static RuleDefinition fromYamlMap(Map<String, Object> fields) {
        return new RuleDefinition(
                (boolean) fields.getOrDefault("loaded", false),
                (String) fields.getOrDefault("name", ""),
                (String) fields.getOrDefault("f_regex", ""),
                (String) fields.getOrDefault("s_regex", ""),
                (String) fields.getOrDefault("format", "{0}"),
                (String) fields.getOrDefault("color", "gray"),
                (String) fields.getOrDefault("scope", "any"),
                (String) fields.getOrDefault("engine", "nfa"),
                (boolean) fields.getOrDefault("sensitive", false)
        );
    }
}
