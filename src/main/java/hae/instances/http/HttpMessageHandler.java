package hae.instances.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import hae.Config;
import hae.component.board.message.MessageTableModel;
import hae.instances.http.utils.MessageProcessor;
import hae.utils.string.StringProcessor;

import java.util.*;

public class HttpMessageHandler implements HttpHandler {
    private final MontoyaApi api;
    private MessageTableModel messageTableModel;
    private final MessageProcessor messageProcessor;
    private String host;

    // Montoya API对HTTP消息的处理分为了请求和响应，因此此处设置高亮和标记需要使用全局变量的方式，以此兼顾请求和响应
    // 同时采用 ThreadLocal 来保证多线程并发的情况下全局变量的安全性
    private final ThreadLocal<List<String>> colorList = ThreadLocal.withInitial(ArrayList::new);
    private final ThreadLocal<List<String>> commentList = ThreadLocal.withInitial(ArrayList::new);
    private final ThreadLocal<Boolean> matches = ThreadLocal.withInitial(() -> false);
    private final ThreadLocal<HttpRequest> httpRequest = new ThreadLocal<>();

    public HttpMessageHandler(MontoyaApi api, MessageTableModel messageTableModel) {
        this.api = api;
        this.messageTableModel = messageTableModel;
        this.messageProcessor = new MessageProcessor(api);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        colorList.get().clear();
        commentList.get().clear();

        Annotations annotations = httpRequestToBeSent.annotations();

        httpRequest.set(httpRequestToBeSent);

        host = StringProcessor.getHostByUrl(httpRequestToBeSent.url());

        List<String> suffixList = Arrays.asList(Config.suffix.split("\\|"));
        matches.set(suffixList.contains(httpRequestToBeSent.fileExtension()));

        if (!matches.get()) {
            List<Map<String, String>> result = messageProcessor.processRequest(host, httpRequestToBeSent, true);
            setColorAndCommentList(result);
        }

        return RequestToBeSentAction.continueWith(httpRequestToBeSent, annotations);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        Annotations annotations = httpResponseReceived.annotations();

        if (!matches.get()) {
            List<Map<String, String>> result = messageProcessor.processResponse(host, httpResponseReceived, true);
            setColorAndCommentList(result);
            // 设置高亮颜色和注释
            if (!colorList.get().isEmpty() && !commentList.get().isEmpty()) {
                String color = messageProcessor.retrieveFinalColor(messageProcessor.retrieveColorIndices(colorList.get()));
                annotations.setHighlightColor(HighlightColor.highlightColor(color));
                String comment = StringProcessor.mergeComment(String.join(", ", commentList.get()));
                annotations.setNotes(comment);

                HttpRequestResponse httpRequestResponse = HttpRequestResponse.httpRequestResponse(httpRequest.get(), httpResponseReceived);

                // 添加到Databoard
                messageTableModel.add(httpRequestResponse, comment, color);
            }
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived, annotations);
    }

    private void setColorAndCommentList(List<Map<String, String>> result) {
        if (result != null && !result.isEmpty() && result.size() > 0) {
            colorList.get().add(result.get(0).get("color"));
            commentList.get().add(result.get(1).get("comment"));
        }
    }
}
