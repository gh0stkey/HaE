package hae.component.board.message;

import burp.api.montoya.http.message.HttpRequestResponse;

public class MessageEntry {

    private final String comment;
    private final HttpRequestResponse requestResponse;
    private final String url;
    private final String length;
    private final String status;
    private final String color;
    private final String method;
    private final String hash;
    private final String path;

    MessageEntry(HttpRequestResponse requestResponse, String method, String url, String comment, String length, String color, String status, String hash, String path) {
        this.requestResponse = requestResponse;
        this.method = method;
        this.url = url;
        this.comment = comment;
        this.length = length;
        this.color = color;
        this.status = status;
        this.hash = hash;
        this.path = path;
    }

    public String getColor() {
        return this.color;
    }

    public String getUrl() {
        return this.url;
    }

    public String getLength() {
        return this.length;
    }

    public String getComment() {
        return this.comment;
    }

    public String getMethod() {
        return this.method;
    }

    public String getStatus() {
        return this.status;
    }

    public HttpRequestResponse getRequestResponse() {
        return this.requestResponse;
    }

    public String getHash() {
        return this.hash;
    }

    public String getPath() {
        return this.path;
    }
}