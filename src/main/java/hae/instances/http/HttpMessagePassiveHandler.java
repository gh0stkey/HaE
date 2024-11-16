package hae.instances.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import hae.component.board.message.MessageTableModel;
import hae.instances.http.utils.MessageProcessor;
import hae.utils.ConfigLoader;
import hae.utils.http.HttpUtils;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static java.util.Collections.emptyList;

public class HttpMessagePassiveHandler implements ScanCheck {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final HttpUtils httpUtils;
    private final MessageTableModel messageTableModel;
    private final MessageProcessor messageProcessor;

    public HttpMessagePassiveHandler(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel) {
        this.api = api;
        this.configLoader = configLoader;
        this.httpUtils = new HttpUtils(api, configLoader);
        this.messageTableModel = messageTableModel;
        this.messageProcessor = new MessageProcessor(api);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse httpRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return auditResult(emptyList());
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse httpRequestResponse) {
        List<String> colorList = new ArrayList<>();
        List<String> commentList = new ArrayList<>();

        HttpRequest request = httpRequestResponse.request();
        HttpResponse response = httpRequestResponse.response();

        boolean matches = httpUtils.verifyHttpRequestResponse(httpRequestResponse, "Proxy");

        if (!matches) {
            try {
                String host = StringProcessor.getHostByUrl(request.url());
                setColorAndCommentList(messageProcessor.processRequest(host, request, true), colorList, commentList);
                setColorAndCommentList(messageProcessor.processResponse(host, response, true), colorList, commentList);

                String url = request.url();
                String method = request.method();
                String status = String.valueOf(response.statusCode());
                String color = messageProcessor.retrieveFinalColor(messageProcessor.retrieveColorIndices(colorList));
                String comment = StringProcessor.mergeComment(String.join(", ", commentList));
                String length = String.valueOf(response.toByteArray().length());

                new SwingWorker<Void, Void>() {
                    @Override
                    protected Void doInBackground() {
                        messageTableModel.add(httpRequestResponse, url, method, status, length, comment, color, "", "");
                        return null;
                    }
                }.execute();
            } catch (Exception e) {
                api.logging().logToError("passiveAudit: " + e.getMessage());
            }
        }

        return auditResult(emptyList());
    }

    private void setColorAndCommentList(List<Map<String, String>> result, List<String> colorList, List<String> commentList) {
        if (result != null && !result.isEmpty()) {
            colorList.add(result.get(0).get("color"));
            commentList.add(result.get(1).get("comment"));
        }
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }
}
