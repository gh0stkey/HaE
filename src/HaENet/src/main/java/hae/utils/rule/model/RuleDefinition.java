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
    private String validator;
    private int validatorTimeout;
    private int validatorBulk;

    public RuleDefinition(boolean loaded, String name, String firstRegex, String secondRegex,
                          String format, String color, String scope, String engine, boolean sensitive,
                          String validator, int validatorTimeout, int validatorBulk) {
        this.loaded = loaded;
        this.name = name;
        this.firstRegex = firstRegex;
        this.secondRegex = secondRegex;
        this.format = format;
        this.color = color;
        this.scope = scope;
        this.engine = engine;
        this.sensitive = sensitive;
        this.validator = validator;
        this.validatorTimeout = validatorTimeout;
        this.validatorBulk = validatorBulk;
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

    public String getValidator() {
        return validator;
    }

    public int getValidatorTimeout() {
        return validatorTimeout;
    }

    public int getValidatorBulk() {
        return validatorBulk;
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

    public void setValidator(String validator) {
        this.validator = validator;
    }

    public void setValidatorTimeout(int validatorTimeout) {
        this.validatorTimeout = validatorTimeout;
    }

    public void setValidatorBulk(int validatorBulk) {
        this.validatorBulk = validatorBulk;
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
                (boolean) objects[8],
                (String) objects[9],
                (int) objects[10],
                (int) objects[11]
        );
    }

    public Object[] toObjectArray() {
        return new Object[]{loaded, name, firstRegex, secondRegex, format, color, scope, engine, sensitive, validator, validatorTimeout, validatorBulk};
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
        if (validator != null && !validator.isBlank()) {
            Map<String, Object> validatorMap = new LinkedHashMap<>();
            validatorMap.put("command", validator);
            if (validatorTimeout > 0) validatorMap.put("timeout", validatorTimeout);
            if (validatorBulk > 0) validatorMap.put("bulk", validatorBulk);
            fields.put("validator", validatorMap);
        }
        return fields;
    }

    public static RuleDefinition fromYamlMap(Map<String, Object> fields) {
        String validatorCmd = "";
        int timeout = 5000;
        int bulk = 500;

        Object validatorObj = fields.get("validator");
        if (validatorObj instanceof Map) {
            Map<String, Object> vMap = (Map<String, Object>) validatorObj;
            validatorCmd = String.valueOf(vMap.getOrDefault("command", ""));
            timeout = vMap.containsKey("timeout") ? ((Number) vMap.get("timeout")).intValue() : 0;
            bulk = vMap.containsKey("bulk") ? ((Number) vMap.get("bulk")).intValue() : 0;
        }
        return new RuleDefinition(
                (boolean) fields.getOrDefault("loaded", false),
                (String) fields.getOrDefault("name", ""),
                (String) fields.getOrDefault("f_regex", ""),
                (String) fields.getOrDefault("s_regex", ""),
                (String) fields.getOrDefault("format", "{0}"),
                (String) fields.getOrDefault("color", "gray"),
                (String) fields.getOrDefault("scope", "any"),
                (String) fields.getOrDefault("engine", "nfa"),
                (boolean) fields.getOrDefault("sensitive", false),
                validatorCmd,
                timeout,
                bulk
        );
    }
}
