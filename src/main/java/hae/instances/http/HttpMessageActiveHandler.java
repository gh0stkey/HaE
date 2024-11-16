package hae.instances.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import hae.component.board.message.MessageTableModel;
import hae.instances.http.utils.MessageProcessor;
import hae.utils.ConfigLoader;
import hae.utils.http.HttpUtils;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HttpMessageActiveHandler implements HttpHandler {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final HttpUtils httpUtils;
    private final MessageTableModel messageTableModel;
    private final MessageProcessor messageProcessor;

    // Montoya API对HTTP消息的处理分为了请求和响应，因此此处设置高亮和标记需要使用全局变量的方式，以此兼顾请求和响应
    // 同时采用 ThreadLocal 来保证多线程并发的情况下全局变量的安全性
    private final ThreadLocal<String> host = ThreadLocal.withInitial(() -> "");
    private final ThreadLocal<List<String>> colorList = ThreadLocal.withInitial(ArrayList::new);
    private final ThreadLocal<List<String>> commentList = ThreadLocal.withInitial(ArrayList::new);

    public HttpMessageActiveHandler(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel) {
        this.api = api;
        this.configLoader = configLoader;
        this.httpUtils = new HttpUtils(api, configLoader);
        this.messageTableModel = messageTableModel;
        this.messageProcessor = new MessageProcessor(api);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        colorList.get().clear();
        commentList.get().clear();

        Annotations annotations = httpRequestToBeSent.annotations();

        try {
            host.set(StringProcessor.getHostByUrl(httpRequestToBeSent.url()));
        } catch (Exception e) {
            api.logging().logToError("handleHttpRequestToBeSent: " + e.getMessage());
        }

        return RequestToBeSentAction.continueWith(httpRequestToBeSent, annotations);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        Annotations annotations = httpResponseReceived.annotations();
        HttpRequest request = httpResponseReceived.initiatingRequest();
        HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(request, httpResponseReceived);
        String toolType = httpResponseReceived.toolSource().toolType().toolName();

        boolean matches = httpUtils.verifyHttpRequestResponse(requestResponse, toolType);

        if (!matches) {
            try {
                setColorAndCommentList(messageProcessor.processRequest(host.get(), request, true));
                setColorAndCommentList(messageProcessor.processResponse(host.get(), httpResponseReceived, true));

                if (!colorList.get().isEmpty() && !commentList.get().isEmpty()) {
                    HttpRequestResponse httpRequestResponse = HttpRequestResponse.httpRequestResponse(request, httpResponseReceived);

                    String color = messageProcessor.retrieveFinalColor(messageProcessor.retrieveColorIndices(colorList.get()));
                    annotations.setHighlightColor(HighlightColor.highlightColor(color));
                    String comment = StringProcessor.mergeComment(String.join(", ", commentList.get()));
                    annotations.setNotes(comment);

                    String method = request.method();
                    String url = request.url();
                    String status = String.valueOf(httpResponseReceived.statusCode());
                    String length = String.valueOf(httpResponseReceived.toByteArray().length());

                    new SwingWorker<Void, Void>() {
                        @Override
                        protected Void doInBackground() {
                            messageTableModel.add(httpRequestResponse, url, method, status, length, comment, color, "", "");
                            return null;
                        }
                    }.execute();
                }
            } catch (Exception e) {
                api.logging().logToError("handleHttpResponseReceived: " + e.getMessage());
            }
        }

        return ResponseReceivedAction.continueWith(httpResponseReceived, annotations);
    }

    private void setColorAndCommentList(List<Map<String, String>> result) {
        if (result != null && !result.isEmpty()) {
            colorList.get().add(result.get(0).get("color"));
            commentList.get().add(result.get(1).get("comment"));
        }
    }
}
