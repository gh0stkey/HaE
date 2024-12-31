package hae.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import hae.component.board.message.MessageTableModel;
import hae.instances.http.utils.RegularMatcher;

public class DataManager {
    private final MontoyaApi api;
    private final Persistence persistence;

    public DataManager(MontoyaApi api) {
        this.api = api;
        this.persistence = api.persistence();
    }

    public synchronized void putData(String dataType, String dataName, PersistedObject persistedObject) {
        if (persistence.extensionData().getChildObject(dataName) != null) {
            persistence.extensionData().deleteChildObject(dataName);
        }
        persistence.extensionData().setChildObject(dataName, persistedObject);
        saveIndex(dataType, dataName);
    }

    public void loadData(MessageTableModel messageTableModel) {
        // 1. 获取索引
        PersistedList<String> dataIndex = persistence.extensionData().getStringList("data"); // 数据索引
        PersistedList<String> messageIndex = persistence.extensionData().getStringList("message"); // 消息索引

        // 2. 从索引获取数据
        loadHaEData(dataIndex);
        loadMessageData(messageIndex, messageTableModel);
    }

    private void saveIndex(String indexName, String indexValue) {
        PersistedList<String> indexList = persistence.extensionData().getStringList(indexName);

        if (indexList != null && !indexList.isEmpty()) {
            persistence.extensionData().deleteStringList(indexName);
        } else {
            indexList = PersistedList.persistedStringList();
        }

        if (!indexList.contains(indexValue)) {
            indexList.add(indexValue);
        }

        persistence.extensionData().setStringList(indexName, indexList);
    }

    private void loadHaEData(PersistedList<String> dataIndex) {
        if (dataIndex != null && !dataIndex.isEmpty()) {
            dataIndex.parallelStream().forEach(index -> {
                PersistedObject dataObj = persistence.extensionData().getChildObject(index);
                dataObj.stringListKeys().forEach(dataKey -> {
                    RegularMatcher.putDataToGlobalMap(api, index, dataKey, dataObj.getStringList(dataKey).stream().toList(), false);
                });
            });
        }
    }

    private void loadMessageData(PersistedList<String> messageIndex, MessageTableModel messageTableModel) {
        if (messageIndex != null && !messageIndex.isEmpty()) {
            messageIndex.parallelStream().forEach(index -> {
                PersistedObject dataObj = persistence.extensionData().getChildObject(index);
                if (dataObj != null) {
                    HttpRequestResponse messageInfo = dataObj.getHttpRequestResponse("messageInfo");
                    String comment = dataObj.getString("comment");
                    String color = dataObj.getString("color");
                    HttpRequest request = messageInfo.request();
                    HttpResponse response = messageInfo.response();
                    String method = request.method();
                    String url = request.url();
                    String status = String.valueOf(response.statusCode());
                    String length = String.valueOf(response.toByteArray().length());
                    messageTableModel.add(messageInfo, url, method, status, length, comment, color, false);
                }
            });
        }
    }
}
