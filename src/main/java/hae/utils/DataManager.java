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

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    public synchronized void loadData(MessageTableModel messageTableModel) {
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
        } else if (indexList == null) {
            indexList = PersistedList.persistedStringList();
        }

        if (!indexList.contains(indexValue)) {
            indexList.add(indexValue);
        }

        persistence.extensionData().setStringList(indexName, indexList);
    }

    private void loadHaEData(PersistedList<String> dataIndex) {
        if (dataIndex != null && !dataIndex.isEmpty()) {
            dataIndex.forEach(index -> {
                PersistedObject dataObj = persistence.extensionData().getChildObject(index);
                try {
                    dataObj.stringListKeys().forEach(dataKey -> RegularMatcher.putDataToGlobalMap(api, index, dataKey, dataObj.getStringList(dataKey).stream().toList(), false));
                } catch (Exception ignored) {
                }
            });
        }
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
        final int threadCount = Math.max(8, Runtime.getRuntime().availableProcessors() * 2);
        ExecutorService executorService = Executors.newWorkStealingPool(threadCount);

        try {
            // 分批处理
            for (int i = 0; i < indexList.size(); i += batchSize) {
                int endIndex = Math.min(i + batchSize, indexList.size());
                List<String> batch = indexList.subList(i, endIndex);

                processBatch(batch, messageTableModel);
            }
        } finally {
            executorService.shutdown();
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
                api.logging().logToError("处理消息数据时出错: " + e.getMessage() + ", index: " + index);
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