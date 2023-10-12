package burp.core.processor;

import burp.IExtensionHelpers;
import burp.core.utils.MatchTool;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MessageProcessor {
    MatchTool matcher = new MatchTool();
    DataProcessingUnit dataProcessingUnit = new DataProcessingUnit();
    ColorProcessor colorProcessor = new ColorProcessor();

    public List<Map<String, String>> processMessage(IExtensionHelpers helpers, byte[] content, boolean isRequest, boolean messageInfo, String host)
            throws NoSuchAlgorithmException {
        List<Map<String, String>> result = new ArrayList<>();
        Map<String, Map<String, Object>> obj;

        if (isRequest) {
            List<String> requestTmpHeaders = helpers.analyzeRequest(content).getHeaders();
            String requestHeaders = String.join("\n", requestTmpHeaders);

            try {
                String urlString = requestTmpHeaders.get(0).split(" ")[1];
                urlString = urlString.indexOf("?") > 0 ? urlString.substring(0, urlString.indexOf("?")) : urlString;
                if (matcher.matchUrlSuffix(urlString)) {
                    return result;
                }
            } catch (Exception e) {
                return result;
            }

            int requestBodyOffset = helpers.analyzeRequest(content).getBodyOffset();
            byte[] requestBody = Arrays.copyOfRange(content, requestBodyOffset, content.length);
            obj = dataProcessingUnit.matchContentByRegex(content, requestHeaders, requestBody, "request", host);
        } else {
            try {
                String inferredMimeType = String.format("hae.%s", helpers.analyzeResponse(content).getInferredMimeType().toLowerCase());
                String statedMimeType = String.format("hae.%s", helpers.analyzeResponse(content).getStatedMimeType().toLowerCase());
                if (matcher.matchUrlSuffix(statedMimeType) || matcher.matchUrlSuffix(inferredMimeType)) {
                    return result;
                }
            } catch (Exception e) {
                return result;
            }
            List<String> responseTmpHeaders = helpers.analyzeResponse(content).getHeaders();
            String responseHeaders = String.join("\n", responseTmpHeaders);
            int responseBodyOffset = helpers.analyzeResponse(content).getBodyOffset();
            byte[] responseBody = Arrays.copyOfRange(content, responseBodyOffset, content.length);
            obj = dataProcessingUnit.matchContentByRegex(content, responseHeaders, responseBody, "response", host);
        }

        if (obj.size() > 0) {
            if (messageInfo) {
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
                    result.add(colorMap);
                    result.add(commentMap);
                }
            } else {
                result.add(dataProcessingUnit.extractDataFromMap(obj));
            }
        }
        return result;
    }
}
