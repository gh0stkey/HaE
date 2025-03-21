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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
                    dataObj.stringListKeys().forEach(dataKey -> {
                        RegularMatcher.putDataToGlobalMap(api, index, dataKey, dataObj.getStringList(dataKey).stream().toList(), false);
                    });
                } catch (Exception ignored) {
                }
            });
        }
    }

    private void loadMessageData(PersistedList<String> messageIndex, MessageTableModel messageTableModel) {
        if (messageIndex == null || messageIndex.isEmpty()) {
            return;
        }

        List<String> indexList = new ArrayList<>();
        for (Object item : messageIndex) {
            try {
                if (item != null) {
                    indexList.add(item.toString());
                }
            } catch (Exception e) {
                api.logging().logToError("转换索引时出错: " + e.getMessage());
            }
        }

        final int batchSize = 2000; // 增加批处理大小
        final int threadCount = Math.max(8, Runtime.getRuntime().availableProcessors() * 2); // 增加线程数
        int totalSize = indexList.size();

        // 使用更高效的线程池
        ExecutorService executorService = Executors.newWorkStealingPool(threadCount);
        List<Future<List<Object[]>>> futures = new ArrayList<>();

        // 分批并行处理数据
        for (int i = 0; i < totalSize; i += batchSize) {
            int endIndex = Math.min(i + batchSize, totalSize);
            List<String> batch = indexList.subList(i, endIndex);

            Future<List<Object[]>> future = executorService.submit(() -> processBatchParallel(batch));
            futures.add(future);
        }

        // 批量添加数据到模型
        try {
            for (Future<List<Object[]>> future : futures) {
                List<Object[]> batchData = future.get();
                messageTableModel.addBatch(batchData);
            }
        } catch (Exception e) {
            api.logging().logToError("批量添加数据时出错: " + e.getMessage());
        } finally {
            executorService.shutdown();
        }
    }

    private List<Object[]> processBatchParallel(List<String> batch) {
        List<Object[]> batchData = new ArrayList<>();
        for (String index : batch) {
            try {
                PersistedObject dataObj = persistence.extensionData().getChildObject(index);
                if (dataObj != null) {
                    HttpRequestResponse messageInfo = dataObj.getHttpRequestResponse("messageInfo");
                    if (messageInfo != null) {
                        batchData.add(prepareMessageData(messageInfo, dataObj));
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("处理消息数据时出错: " + e.getMessage() + ", index: " + index);
            }
        }
        return batchData;
    }

    private Object[] prepareMessageData(HttpRequestResponse messageInfo, PersistedObject dataObj) {
        HttpRequest request = messageInfo.request();
        HttpResponse response = messageInfo.response();
        return new Object[]{
                messageInfo,
                request.url(),
                request.method(),
                String.valueOf(response.statusCode()),
                String.valueOf(response.toByteArray().length()),
                dataObj.getString("comment"),
                dataObj.getString("color"),
                false
        };
    }
}