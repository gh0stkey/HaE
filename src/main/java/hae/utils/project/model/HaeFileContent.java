package hae.utils.project.model;

import burp.api.montoya.MontoyaApi;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HaeFileContent {
    private final MontoyaApi api;
    private String host;
    private String httpPath;
    private final Map<String, List<String>> dataMap;
    private final Map<String, Map<String, String>> urlMap;

    public HaeFileContent(MontoyaApi api) {
        this.api = api;
        this.dataMap = new HashMap<>();
        this.urlMap = new HashMap<>();
    }

    public String getHost() {
        return host;
    }

    public Map<String, List<String>> getDataMap() {
        return dataMap;
    }

    public Map<String, Map<String, String>> getUrlMap() {
        return urlMap;
    }

    public String getHttpPath() {
        return httpPath;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setHttpPath(String path) {
        this.httpPath = path;
    }

    public void setDataMap(Map<String, List<Object>> dataMap) {
        for (Map.Entry<String, List<Object>> entry : dataMap.entrySet()) {
            List<String> values = new ArrayList<>();
            for (Object value : entry.getValue()) {
                try {
                    values.add(new String((byte[]) value, StandardCharsets.UTF_8));
                } catch (Exception e) {
                    values.add(value.toString());
                }
            }
            this.dataMap.put(entry.getKey(), values);
        }
    }

    public void setUrlMap(Map<String, Map<String, Object>> urlMap) {
        for (Map.Entry<String, Map<String, Object>> entry : urlMap.entrySet()) {
            Map<String, String> newValues = new HashMap<>();
            Map<String, Object> values = entry.getValue();
            for (String key : values.keySet()) {
                try {
                    newValues.put(key, new String((byte[]) values.get(key), StandardCharsets.UTF_8));
                } catch (Exception e) {
                    newValues.put(key, values.get(key).toString());
                }
            }
            this.urlMap.put(entry.getKey(), newValues);
        }
    }
}