package hae.component.board.message;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

public class MessageDeduplicator {
    private final ConfigLoader configLoader;

    public MessageDeduplicator(ConfigLoader configLoader) {
        this.configLoader = configLoader;
    }

    public boolean isDuplicate(List<MessageEntry> log, HttpRequestResponse messageInfo,
                               String url, String comment, String color) {
        if (log.isEmpty()) {
            return false;
        }

        String host = StringProcessor.getHostByUrl(url);

        for (MessageEntry entry : log) {
            if (host.equals(StringProcessor.getHostByUrl(entry.getUrl()))) {
                if (isRequestDuplicate(
                        messageInfo, entry.getRequestResponse(),
                        url, entry.getUrl(),
                        comment, entry.getComment(),
                        color, entry.getColor()
                )) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isRequestDuplicate(
            HttpRequestResponse newReq, HttpRequestResponse existingReq,
            String newUrl, String existingUrl,
            String newComment, String existingComment,
            String newColor, String existingColor) {
        try {
            // URL匹配
            String normalizedNewUrl = normalizeUrl(newUrl);
            String normalizedExistingUrl = normalizeUrl(existingUrl);
            boolean urlMatch = normalizedNewUrl.equals(normalizedExistingUrl);

            // 注释和颜色匹配（同规则、同数量、同颜色）
            boolean metadataMatch = areCommentsEqual(newComment, existingComment) &&
                    newColor.equals(existingColor);

            // 元数据不匹配则一定不是重复
            if (!urlMatch || !metadataMatch) {
                return false;
            }

            // 请求体匹配（区分不同POST body）
            byte[] newReqBody = newReq.request().body().getBytes();
            byte[] existingReqBody = existingReq.request().body().getBytes();
            boolean requestBodyMatch = Arrays.equals(newReqBody, existingReqBody);

            // 响应匹配：剥离Dynamic Header后，比对剩余头部 + body
            String newResStripped = stripDynamicHeaders(newReq.response()) + "\r\n\r\n" +
                    new String(newReq.response().body().getBytes(), StandardCharsets.UTF_8);
            String existingResStripped = stripDynamicHeaders(existingReq.response()) + "\r\n\r\n" +
                    new String(existingReq.response().body().getBytes(), StandardCharsets.UTF_8);
            boolean responseMatch = newResStripped.equals(existingResStripped);

            return requestBodyMatch || responseMatch;
        } catch (Exception e) {
            return false;
        }
    }

    private String normalizeUrl(String url) {
        if (url == null) {
            return "";
        }

        String normalized = url.trim().toLowerCase();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        int protocolEnd = normalized.indexOf("://");
        if (protocolEnd >= 0) {
            String protocol = normalized.substring(0, protocolEnd + 3);
            String rest = normalized.substring(protocolEnd + 3).replaceAll("//+", "/");
            return protocol + rest;
        }

        return normalized.replaceAll("//+", "/");
    }

    private String stripDynamicHeaders(HttpResponse response) {
        String dynamicHeader = configLoader.getDynamicHeader();
        if (dynamicHeader == null || dynamicHeader.isBlank()) {
            return response.headers().stream()
                    .map(HttpHeader::toString)
                    .collect(Collectors.joining("\r\n"));
        }

        Set<String> dynamicNames = Arrays.stream(dynamicHeader.split("\\|"))
                .map(String::trim)
                .map(String::toLowerCase)
                .collect(Collectors.toSet());

        return response.headers().stream()
                .filter(h -> !dynamicNames.contains(h.name().toLowerCase()))
                .map(HttpHeader::toString)
                .collect(Collectors.joining("\r\n"));
    }

    private boolean areCommentsEqual(String comment1, String comment2) {
        if (comment1 == null || comment2 == null) {
            return false;
        }

        try {
            Set<String> rules1 = new TreeSet<>(Arrays.asList(comment1.split(", ")));
            Set<String> rules2 = new TreeSet<>(Arrays.asList(comment2.split(", ")));
            return rules1.equals(rules2);
        } catch (Exception e) {
            return false;
        }
    }
}
