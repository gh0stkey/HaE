package hae.component.board.message;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import hae.repository.RuleRepository;
import hae.utils.rule.model.RuleDefinition;
import hae.utils.string.StringProcessor;

import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public class MessageFilter {
    private final RuleRepository ruleRepository;

    public MessageFilter(RuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    public List<MessageEntry> filterByHost(List<MessageEntry> logSnapshot, String filterText) {
        List<MessageEntry> result = new ArrayList<>(logSnapshot.size() / 2);

        boolean isWildcardAll = "*".equals(filterText);
        boolean isWildcardFilter = filterText.contains("*");
        String normalizedFilter = filterText.toLowerCase().trim();

        logSnapshot.parallelStream()
                .filter(entry -> {
                    if (isWildcardAll) {
                        return true;
                    }

                    try {
                        String host = StringProcessor.getHostByUrl(entry.getUrl());
                        if (host.isEmpty()) {
                            return false;
                        }

                        return StringProcessor.matchesHostPattern(host, filterText) ||
                                (isWildcardFilter && host.toLowerCase().contains(normalizedFilter.replace("*", "")));
                    } catch (Exception e) {
                        return false;
                    }
                })
                .forEachOrdered(result::add);

        return result;
    }

    public List<MessageEntry> filterByComment(List<MessageEntry> logSnapshot, String tableName) {
        List<MessageEntry> result = new ArrayList<>();

        for (MessageEntry entry : logSnapshot) {
            if (entry.getComment().contains(tableName)) {
                result.add(entry);
            }
        }

        return result;
    }

    public List<MessageEntry> filterByMessage(List<MessageEntry> logSnapshot, String tableName, String filterText) {
        List<MessageEntry> result = new ArrayList<>();

        for (MessageEntry entry : logSnapshot) {
            try {
                AtomicBoolean isMatched = new AtomicBoolean(false);

                HttpRequestResponse requestResponse = entry.getRequestResponse();
                HttpRequest httpRequest = requestResponse.request();
                HttpResponse httpResponse = requestResponse.response();

                String requestString = new String(httpRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
                String requestBody = new String(httpRequest.body().getBytes(), StandardCharsets.UTF_8);
                String requestHeaders = httpRequest.headers().stream()
                        .map(HttpHeader::toString)
                        .collect(Collectors.joining("\r\n"));

                String responseString = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
                String responseBody = new String(httpResponse.body().getBytes(), StandardCharsets.UTF_8);
                String responseHeaders = httpResponse.headers().stream()
                        .map(HttpHeader::toString)
                        .collect(Collectors.joining("\r\n"));

                ruleRepository.getAllGroupNames().forEach(i -> {
                    for (RuleDefinition rule : ruleRepository.getRulesByGroup(i)) {
                        String name = rule.getName();
                        String format = rule.getFormat();
                        String scope = rule.getScope();

                        // 从注释中查看是否包含当前规则名，包含的再进行查询
                        if (entry.getComment().contains(name)) {
                            if (name.equals(tableName)) {
                                boolean isMatch = matchByScope(scope, format, filterText,
                                        requestString, requestHeaders, requestBody,
                                        responseString, responseHeaders, responseBody);

                                isMatched.set(isMatch);
                                break;
                            }
                        }
                    }
                });

                // 由于每个用户规则不同，如果进行项目文件共享则需要考虑全部匹配一下
                if (!isMatched.get()) {
                    isMatched.set(matchingString("{0}", filterText, requestString) ||
                            matchingString("{0}", filterText, responseString));
                }

                if (isMatched.get()) {
                    result.add(entry);
                }
            } catch (Exception ignored) {
                // 跳过异常条目，继续处理其余条目
            }
        }

        return result;
    }

    private boolean matchByScope(String scope, String format, String filterText,
                                 String requestString, String requestHeaders, String requestBody,
                                 String responseString, String responseHeaders, String responseBody) {
        return switch (scope) {
            case "any" -> matchingString(format, filterText, requestString) ||
                    matchingString(format, filterText, responseString);
            case "request" -> matchingString(format, filterText, requestString);
            case "response" -> matchingString(format, filterText, responseString);
            case "any header" -> matchingString(format, filterText, requestHeaders) ||
                    matchingString(format, filterText, responseHeaders);
            case "request header" -> matchingString(format, filterText, requestHeaders);
            case "response header" -> matchingString(format, filterText, responseHeaders);
            case "any body" -> matchingString(format, filterText, requestBody) ||
                    matchingString(format, filterText, responseBody);
            case "request body" -> matchingString(format, filterText, requestBody);
            case "response body" -> matchingString(format, filterText, responseBody);
            case "request line" -> {
                String requestLine = requestString.split("\\r?\\n", 2)[0];
                yield matchingString(format, filterText, requestLine);
            }
            case "response line" -> {
                String responseLine = responseString.split("\\r?\\n", 2)[0];
                yield matchingString(format, filterText, responseLine);
            }
            default -> false;
        };
    }

    private boolean matchingString(String format, String filterText, String target) {
        boolean isMatch = true;

        try {
            MessageFormat mf = new MessageFormat(format);
            Object[] parsedObjects = mf.parse(filterText);

            for (Object parsedObject : parsedObjects) {
                if (!target.contains(parsedObject.toString())) {
                    isMatch = false;
                    break;
                }
            }
        } catch (Exception e) {
            isMatch = false;
        }

        return isMatch;
    }
}
