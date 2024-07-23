package hae.component.board.table;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import hae.Config;
import hae.utils.ConfigLoader;
import hae.utils.http.HttpUtils;
import okhttp3.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AIPower {
    private final MontoyaApi api;
    private final HttpUtils httpUtils;
    private final ConfigLoader configLoader;
    private final String apiAuth;
    private final String aiModel;
    private final String aiBaseUrl;

    public AIPower(MontoyaApi api, ConfigLoader configLoader, String aiModel, String aiBaseUrl, String[] apiKey) {
        this.api = api;
        this.configLoader = configLoader;
        this.httpUtils = new HttpUtils(api);
        this.aiModel = aiModel;
        this.aiBaseUrl = aiBaseUrl;

        this.apiAuth = String.format("Bearer %s", apiKey[new Random().nextInt(apiKey.length)]);
    }

    // Stream Response
    public String chatWithAPI(String ruleName, String data) {
        OkHttpClient httpClient = new OkHttpClient();
        String fileId = uploadFileToAIService(ruleName, data);
        Gson gson = new Gson();

        if (fileId != null) {
            String chatUrl = String.format("%s/chat/completions", aiBaseUrl);
            String chatMessage = generateJsonData(configLoader.getAIPrompt(), fileId);
            Request request = new Request.Builder()
                    .url(chatUrl)
                    .header("Authorization", apiAuth)
                    .post(RequestBody.create(MediaType.parse("application/json"), chatMessage))
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new IOException("Unexpected code " + response);
                }

                BufferedReader reader = new BufferedReader(new InputStreamReader(response.body().byteStream()));
                StringBuilder chatReturn = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("data: ") && !line.contains("[DONE]")) {
                        String jsonData = line.substring(6);
                        Type type = new TypeToken<Map<String, Object>>() {
                        }.getType();
                        Map<String, Object> map = gson.fromJson(jsonData, type);
                        String content = getDeltaContent(map);
                        if (content != null) {
                            chatReturn.append(content);
                        }
                    }
                }

                deleteFileOnAIService(fileId);

                return chatReturn.toString();
            } catch (Exception e) {
                return "";
            }
        }

        return "";
    }

    private String getDeltaContent(Map<String, Object> map) {
        List<Map<String, Map<String, String>>> choices = (List<Map<String, Map<String, String>>>) map.get("choices");
        if (choices != null && !choices.isEmpty()) {
            Map<String, String> delta = choices.get(0).get("delta");
            return delta.get("content");
        }
        return null;
    }

    private String uploadFileToAIService(String ruleName, String data) {
        String uploadUrl = String.format("%s/files", aiBaseUrl);
        String uploadParam = "file";
        String filename = "hae.txt";
        String content = String.format(Config.userTextFormat, ruleName, data);

        HttpRequest uploadFileRequest = httpUtils.generateRequestByMultipartUploadMethod(uploadUrl, uploadParam, filename, content).withAddedHeader("Authorization", apiAuth);

        HttpRequestResponse uploadFileRequestResponse = api.http().sendRequest(uploadFileRequest, RequestOptions.requestOptions().withUpstreamTLSVerification());
        String responseBody = uploadFileRequestResponse.response().bodyToString();
        Pattern pattern = Pattern.compile("\"id\":\"(.*?)\",");
        Matcher matcher = pattern.matcher(responseBody);

        return matcher.find() ? matcher.group(1) : null;
    }

    private void deleteFileOnAIService(String fileId) {
        String deleteFileUrl = String.format("%s/files/%s", aiBaseUrl, fileId);
        HttpRequest deleteFileRequest = httpUtils.generateRequestByDeleteMethod(deleteFileUrl).withAddedHeader("Authorization", apiAuth);
        api.http().sendRequest(deleteFileRequest, RequestOptions.requestOptions().withUpstreamTLSVerification());
    }

    private String getFileContentOnAiService(String fileId) {
        String getFileContentUrl = String.format("%s/files/%s/content", aiBaseUrl, fileId);
        HttpRequest getFileContentRequest = HttpRequest.httpRequestFromUrl(getFileContentUrl).withAddedHeader("Authorization", apiAuth);
        HttpRequestResponse getFileRequestResponse = api.http().sendRequest(getFileContentRequest, RequestOptions.requestOptions().withUpstreamTLSVerification());
        String responseBody = getFileRequestResponse.response().bodyToString();
        Pattern pattern = Pattern.compile("\"content\":\"(.*?)\",\"file_type\"");
        Matcher matcher = pattern.matcher(responseBody);

        return matcher.find() ? matcher.group(1) : null;
    }

    private String generateJsonData(String prompt, String fileId) {
        Map<String, Object> data = new HashMap<>();
        data.put("model", aiModel);
        data.put("stream", true);
        data.put("messages", new Object[]{
                new HashMap<String, Object>() {{
                    put("role", "system");
                    put("content", prompt);
                }},
                new HashMap<String, Object>() {{
                    put("role", "system");
                    put("content", aiModel.equals("qwen-long") ? String.format("fileid://%s", fileId) : getFileContentOnAiService(fileId));
                }},
                new HashMap<String, Object>() {{
                    put("role", "user");
                    put("content", "Start");
                }}
        });

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(data);
    }

}
