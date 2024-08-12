package hae.utils.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.utilities.RandomUtils;
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;

import java.util.Arrays;
import java.util.List;

public class HttpUtils {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;

    public HttpUtils(MontoyaApi api, ConfigLoader configLoader) {
        this.api = api;
        this.configLoader = configLoader;
    }

    public HttpRequest generateRequestByMultipartUploadMethod(String url, String name, String filename, String content) {
        HttpRequest baseRequest = HttpRequest.httpRequestFromUrl(url).withTransformationApplied(HttpTransformation.TOGGLE_METHOD);

        String boundary = api.utilities().randomUtils().randomString(32, RandomUtils.CharacterSet.ASCII_LETTERS);

        StringBuilder newBody = new StringBuilder();
        newBody.append(String.format("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n\r\n%s\r\n", boundary, name, filename, content));
        newBody.append(String.format("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n", boundary, "purpose", "file-extract"));
        newBody.append("--").append(boundary).append("--\r\n");

        baseRequest = baseRequest.withUpdatedHeader("Content-Type", "multipart/form-data; boundary=" + boundary).withBody(newBody.toString());

        return baseRequest;
    }


    public HttpRequest generateRequestByDeleteMethod(String url) {
        return HttpRequest.httpRequestFromUrl(url).withMethod("DELETE");
    }

    public boolean verifyHttpRequestResponse(HttpRequestResponse requestResponse, String toolType) {
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();

        String host = StringProcessor.getHostByUrl(request.url());
        String[] hostList = configLoader.getBlockHost().split("\\|");
        boolean isBlockHost = isBlockHost(hostList, host);

        List<String> suffixList = Arrays.asList(configLoader.getExcludeSuffix().split("\\|"));
        boolean isExcludeSuffix = suffixList.contains(request.fileExtension().toLowerCase());

        boolean isToolScope = !configLoader.getScope().contains(toolType);

        List<String> statusList = Arrays.asList(configLoader.getExcludeStatus().split("\\|"));
        boolean isExcludeStatus = statusList.contains(String.valueOf(response.statusCode()));

        return isExcludeSuffix || isBlockHost || isToolScope || isExcludeStatus;
    }

    private boolean isBlockHost(String[] hostList, String host) {
        boolean isBlockHost = false;
        for (String hostName : hostList) {
            String cleanedHost = StringProcessor.replaceFirstOccurrence(hostName, "*.", "");
            if (hostName.contains("*.") && StringProcessor.matchFromEnd(host, cleanedHost)) {
                isBlockHost = true;
            } else if (host.equals(hostName) || hostName.equals("*")) {
                isBlockHost = true;
            }
        }
        return isBlockHost;
    }
}
