package hae.instances.http.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import hae.Config;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class MessageProcessor {
    private final MontoyaApi api;
    private final RegularMatcher regularMatcher;

    private String finalColor = "";

    public MessageProcessor(MontoyaApi api) {
        this.api = api;
        this.regularMatcher = new RegularMatcher(api);
    }

    public List<Map<String, String>> processMessage(String host, String message, boolean flag) {
        Map<String, Map<String, Object>> obj = null;

        try {
            obj = regularMatcher.match(host, "any", message, message, message);
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
                    .collect(Collectors.joining("\n"));

            obj = regularMatcher.match(host, "response", response, header, body);
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
                    .collect(Collectors.joining("\n"));

            obj = regularMatcher.match(host, "request", request, header, body);
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
                    Map<String, String> colorMap = new HashMap<String, String>() {{
                        put("color", color);
                    }};
                    Map<String, String> commentMap = new HashMap<String, String>() {{
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

    private void upgradeColors(List<Integer> colorList) {
        int colorSize = colorList.size();
        String[] colorArray = Config.color;
        colorList.sort(Comparator.comparingInt(Integer::intValue));
        int i = 0;
        List<Integer> stack = new ArrayList<>();
        while (i < colorSize) {
            if (stack.isEmpty()) {
                stack.add(colorList.get(i));
            } else {
                if (!Objects.equals(colorList.get(i), stack.stream().reduce((first, second) -> second).orElse(99999999))) {
                    stack.add(colorList.get(i));
                } else {
                    stack.set(stack.size() - 1, stack.get(stack.size() - 1) - 1);
                }
            }
            i++;
        }
        // 利用HashSet删除重复元素
        HashSet tmpList = new HashSet(stack);
        if (stack.size() == tmpList.size()) {
            stack.sort(Comparator.comparingInt(Integer::intValue));
            if (stack.get(0) < 0) {
                finalColor = colorArray[0];
            } else {
                finalColor = colorArray[stack.get(0)];
            }
        } else {
            upgradeColors(stack);
        }
    }

    public String retrieveFinalColor(List<Integer> colorList) {
        upgradeColors(colorList);
        return finalColor;
    }

}
