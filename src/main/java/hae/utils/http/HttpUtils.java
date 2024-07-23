package hae.utils.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;
import burp.api.montoya.utilities.RandomUtils;

public class HttpUtils {
    private final MontoyaApi api;

    public HttpUtils(MontoyaApi api) {
        this.api = api;
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

    public HttpRequest generateRequestByJsonMethod(String url, String data) {
        HttpRequest baseRequest = HttpRequest.httpRequestFromUrl(url).withTransformationApplied(HttpTransformation.TOGGLE_METHOD);
        HttpService baseService = baseRequest.httpService();
        String requestString = baseRequest.toString().replace("application/x-www-form-urlencoded", "application/json");
        baseRequest = HttpRequest.httpRequest(baseService, requestString).withBody(data);
        return baseRequest;
    }

    public HttpRequest generateRequestByDeleteMethod(String url) {
        return HttpRequest.httpRequestFromUrl(url).withMethod("DELETE");
    }
}
