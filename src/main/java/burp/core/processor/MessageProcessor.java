package burp.core.processor;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.core.utils.MatchTool;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MessageProcessor {
    private MatchTool matcher = new MatchTool();
    private DataProcessingUnit dataProcessingUnit = new DataProcessingUnit();
    private ColorProcessor colorProcessor = new ColorProcessor();

    public List<Map<String, String>> processMessage(IExtensionHelpers helpers, IHttpRequestResponse messageInfo, String host, boolean actionFlag) throws Exception {

        byte[] requestByte = messageInfo.getRequest();
        byte[] responseByte = messageInfo.getResponse();

        List<Map<String, String>> reqObj = processRequestMessage(helpers, requestByte, host, actionFlag);
        List<Map<String, String>> resObj = processResponseMessage(helpers, responseByte, host, actionFlag);
        List<Map<String, String>> mergedList = new ArrayList<>();

        if (reqObj != null && !reqObj.isEmpty()) {
            if (resObj != null && !resObj.isEmpty()) {
                List<String> colorList = new ArrayList<>();

                colorList.add(reqObj.get(0).get("color"));
                colorList.add(resObj.get(0).get("color"));
                Map<String, String> colorMap = new HashMap<>();
                colorMap.put("color", colorProcessor.retrieveFinalColor(colorProcessor.retrieveColorIndices(colorList)));

                Map<String, String> commentMap = new HashMap<>();
                String commentList = String.format("%s, %s", reqObj.get(1).get("comment"), resObj.get(1).get("comment"));
                commentMap.put("comment", commentList);

                mergedList.add(0, colorMap);
                mergedList.add(1, commentMap);
            } else {
                mergedList = new ArrayList<>(reqObj);
            }
        } else if (resObj != null && !resObj.isEmpty()){
            mergedList = new ArrayList<>(resObj);
        }

        return mergedList;
    }

    public List<Map<String, String>> processRequestMessage(IExtensionHelpers helpers, byte[] content, String host, boolean actionFlag) throws Exception {
        Map<String, Map<String, Object>> obj;

        IRequestInfo requestInfo = helpers.analyzeRequest(content);
        List<String> requestTmpHeaders = requestInfo.getHeaders();
        String requestHeaders = String.join("\n", requestTmpHeaders);

        try {
            String urlString = requestTmpHeaders.get(0).split(" ")[1];
            urlString = urlString.indexOf("?") > 0 ? urlString.substring(0, urlString.indexOf("?")) : urlString;
            if (matcher.matchUrlSuffix(urlString)) {
                return null;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        int requestBodyOffset = requestInfo.getBodyOffset();
        byte[] requestBody = Arrays.copyOfRange(content, requestBodyOffset, content.length);
        obj = dataProcessingUnit.matchContentByRegex(content, requestHeaders, requestBody, "request", host);

        return getDataList(obj, actionFlag);
    }

    public List<Map<String, String>> processResponseMessage(IExtensionHelpers helpers, byte[] content, String host, boolean actionFlag) throws Exception {
        Map<String, Map<String, Object>> obj;

        IResponseInfo responseInfo = helpers.analyzeResponse(content);
        List<String> responseTmpHeaders = responseInfo.getHeaders();
        String responseHeaders = String.join("\n", responseTmpHeaders);

        int responseBodyOffset = responseInfo.getBodyOffset();
        byte[] responseBody = Arrays.copyOfRange(content, responseBodyOffset, content.length);

        if (responseBody.length > 1) {
            try {
                // TODO: 需要加入文件头校验来排除静态二进制文件
                String inferredMimeType = String.format("hae.%s", responseInfo.getInferredMimeType());
                String statedMimeType = String.format("hae.%s", responseInfo.getStatedMimeType());
                if (matcher.matchUrlSuffix(statedMimeType) || matcher.matchUrlSuffix(inferredMimeType))
                {
                    return null;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        } else {
            return null;
        }

        obj = dataProcessingUnit.matchContentByRegex(content, responseHeaders, responseBody, "response", host);

        return getDataList(obj, actionFlag);
    }

    private List<Map<String, String>> getDataList(Map<String, Map<String, Object>> obj, boolean actionFlag) {
        List<Map<String, String>> highlightList = new ArrayList<>();
        List<Map<String, String>> extractList = new ArrayList<>();

        if (obj.size() > 0) {
            if (actionFlag) {
                List<List<String>> resultList = dataProcessingUnit.extractColorsAndComments(obj);
                List<String> colorList = resultList.get(0);
                List<String> commentList = resultList.get(1);
                if (!colorList.isEmpty() && !commentList.isEmpty()) {
                    String color = colorProcessor.retrieveFinalColor(colorProcessor.retrieveColorIndices(colorList));
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
                extractList.add(dataProcessingUnit.extractDataFromMap(obj));
            }
        }

        return actionFlag ? highlightList : extractList;
    }
}
