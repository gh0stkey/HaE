package hae.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import hae.component.board.message.MessageTableModel;

import java.util.List;
import java.util.Objects;

public class DataManager {
    private final MontoyaApi api;
    private final Persistence persistence;
    private final PersistenceHelper persistenceHelper;

    public DataManager(MontoyaApi api) {
        this.api = api;
        this.persistence = api.persistence();
        this.persistenceHelper = new PersistenceHelper(api.persistence());
    }

    public void putData(String dataType, String dataName, PersistedObject persistedObject) {
        persistenceHelper.putData(dataType, dataName, persistedObject);
    }

    public synchronized void loadData(MessageTableModel messageTableModel) {
        // 获取消息索引
        PersistedList<String> messageIndex = persistence.extensionData().getStringList("message");

        // 从索引加载消息数据
        loadMessageData(messageIndex, messageTableModel);
    }

    private void loadMessageData(PersistedList<String> messageIndex, MessageTableModel messageTableModel) {
        if (messageIndex == null || messageIndex.isEmpty()) {
            return;
        }

        // 直接转换为List，简化处理
        List<String> indexList = messageIndex.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .toList();

        if (indexList.isEmpty()) {
            return;
        }

        final int batchSize = 2000;

        // 分批处理
        for (int i = 0; i < indexList.size(); i += batchSize) {
            int endIndex = Math.min(i + batchSize, indexList.size());
            List<String> batch = indexList.subList(i, endIndex);

            processBatch(batch, messageTableModel);
        }
    }

    private void processBatch(List<String> batch, MessageTableModel messageTableModel) {
        batch.forEach(index -> {
            try {
                PersistedObject dataObj = persistence.extensionData().getChildObject(index);
                if (dataObj != null) {
                    HttpRequestResponse messageInfo = dataObj.getHttpRequestResponse("messageInfo");
                    if (messageInfo != null) {
                        addMessageToModel(messageInfo, dataObj, messageTableModel);
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("processBatch: " + e.getMessage());
            }
        });
    }

    private void addMessageToModel(HttpRequestResponse messageInfo, PersistedObject dataObj, MessageTableModel messageTableModel) {
        HttpRequest request = messageInfo.request();
        HttpResponse response = messageInfo.response();

        messageTableModel.add(
                messageInfo,
                request.url(),
                request.method(),
                String.valueOf(response.statusCode()),
                String.valueOf(response.toByteArray().length()),
                dataObj.getString("comment"),
                dataObj.getString("color"),
                false
        );
    }
}
