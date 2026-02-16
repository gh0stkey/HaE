package hae.instances.http.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import hae.Config;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class MessageProcessor {
    private final MontoyaApi api;
    private final RegularMatcher regularMatcher;

    public MessageProcessor(MontoyaApi api, ConfigLoader configLoader, DataRepository dataRepository, RuleRepository ruleRepository) {
        this.api = api;
        this.regularMatcher = new RegularMatcher(api, configLoader, dataRepository, ruleRepository);
    }

    public List<Map<String, String>> processMessage(String host, String message, boolean flag) {
        Map<String, Map<String, Object>> obj = null;

        try {
            obj = regularMatcher.performRegexMatching(host, "any", message, message, message);
        } catch (Exception ignored) {
        }

        return getDataList(obj, flag);
    }

    public List<Map<String, String>> processResponse(String host, HttpResponse httpResponse, boolean flag) {
        Map<String, Map<String, Object>> obj = null;

        try {
            String response = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
            String body = new String(httpResponse.body().getBytes(), StandardCharsets.UTF_8);
            String header = httpResponse.headers().stream()
                    .map(HttpHeader::toString)
                    .collect(Collectors.joining("\r\n"));

            obj = regularMatcher.performRegexMatching(host, "response", response, header, body);
        } catch (Exception ignored) {
        }

        return getDataList(obj, flag);
    }

    public List<Map<String, String>> processRequest(String host, HttpRequest httpRequest, boolean flag) {
        Map<String, Map<String, Object>> obj = null;

        try {
            String request = new String(httpRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
            String body = new String(httpRequest.body().getBytes(), StandardCharsets.UTF_8);
            String header = httpRequest.headers().stream()
                    .map(HttpHeader::toString)
                    .collect(Collectors.joining("\r\n"));

            obj = regularMatcher.performRegexMatching(host, "request", request, header, body);
        } catch (Exception ignored) {
        }

        return getDataList(obj, flag);
    }

    private List<Map<String, String>> getDataList(Map<String, Map<String, Object>> obj, boolean actionFlag) {
        List<Map<String, String>> highlightList = new ArrayList<>();
        List<Map<String, String>> extractList = new ArrayList<>();

        if (obj != null && !obj.isEmpty()) {
            if (actionFlag) {
                List<List<String>> resultList = extractColorsAndComments(obj);
                List<String> colorList = resultList.get(0);
                List<String> commentList = resultList.get(1);
                if (!colorList.isEmpty() && !commentList.isEmpty()) {
                    String color = retrieveFinalColor(retrieveColorIndices(colorList));
                    Map<String, String> colorMap = new HashMap<>() {{
                        put("color", color);
                    }};
                    Map<String, String> commentMap = new HashMap<>() {{
                        put("comment", String.join(", ", commentList));
                    }};
                    highlightList.add(colorMap);
                    highlightList.add(commentMap);
                }
            } else {
                extractList.add(extractDataFromMap(obj));
            }
        }

        return actionFlag ? highlightList : extractList;
    }

    private Map<String, String> extractDataFromMap(Map<String, Map<String, Object>> inputData) {
        Map<String, String> extractedData = new HashMap<>();
        inputData.keySet().forEach(key -> {
            Map<String, Object> tempMap = inputData.get(key);
            String data = tempMap.get("data").toString();
            extractedData.put(key, data);
        });

        return extractedData;
    }

    private List<List<String>> extractColorsAndComments(Map<String, Map<String, Object>> inputData) {
        List<String> colorList = new ArrayList<>();
        List<String> commentList = new ArrayList<>();
        inputData.keySet().forEach(key -> {
            Map<String, Object> tempMap = inputData.get(key);
            String color = tempMap.get("color").toString();
            colorList.add(color);
            commentList.add(key);
        });
        List<List<String>> result = new ArrayList<>();
        result.add(colorList);
        result.add(commentList);

        return result;
    }

    public List<Integer> retrieveColorIndices(List<String> colors) {
        List<Integer> indices = new ArrayList<>();
        String[] colorArray = Config.color;
        int size = colorArray.length;

        for (String color : colors) {
            for (int i = 0; i < size; i++) {
                if (colorArray[i].equals(color)) {
                    indices.add(i);
                }
            }
        }

        return indices;
    }

    private String upgradeColors(List<Integer> colorList) {
        if (colorList == null || colorList.isEmpty()) {
            return Config.color[0];
        }

        // 创建副本避免修改原始数据
        List<Integer> indices = new ArrayList<>(colorList);
        indices.sort(Comparator.comparingInt(Integer::intValue));

        // 处理颜色升级
        for (int i = 1; i < indices.size(); i++) {
            if (indices.get(i).equals(indices.get(i - 1))) {
                // 如果发现重复的颜色索引，将当前索引降级
                indices.set(i - 1, indices.get(i - 1) - 1);
            }
        }

        // 获取最终的颜色索引
        int finalIndex = indices.stream()
                .min(Integer::compareTo)
                .orElse(0);

        // 处理负数索引情况
        if (finalIndex < 0) {
            return Config.color[0];
        }

        return Config.color[finalIndex];
    }

    public String retrieveFinalColor(List<Integer> colorList) {
        return upgradeColors(colorList);
    }

}
