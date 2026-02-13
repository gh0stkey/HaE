package hae.repository.impl;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import hae.repository.DataRepository;
import hae.utils.string.StringProcessor;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class DataRepositoryImpl implements DataRepository {
    private final ConcurrentHashMap<String, Map<String, List<String>>> dataMap = new ConcurrentHashMap<>();
    private final MontoyaApi api;
    private final Persistence persistence;

    public DataRepositoryImpl(MontoyaApi api) {
        this.api = api;
        this.persistence = api.persistence();
    }

    @Override
    public Map<String, List<String>> getByHost(String host) {
        return dataMap.get(host);
    }

    @Override
    public Set<String> getAllHosts() {
        return dataMap.keySet();
    }

    @Override
    public boolean containsHost(String host) {
        return dataMap.containsKey(host);
    }

    @Override
    public boolean isEmpty() {
        return dataMap.isEmpty();
    }

    @Override
    public int size() {
        return dataMap.size();
    }

    @Override
    public Map<String, Map<String, List<String>>> getAll() {
        return dataMap;
    }

    @Override
    public synchronized void mergeData(String host, String ruleName, List<String> data, boolean persist) {
        if (Objects.equals(host, "") || host == null) {
            return;
        }

        dataMap.compute(host, (existingHost, existingMap) -> {
            Map<String, List<String>> gRuleMap = Optional.ofNullable(existingMap).orElse(new ConcurrentHashMap<>());

            gRuleMap.merge(ruleName, new ArrayList<>(data), (existingList, newList) -> {
                Set<String> combinedSet = new LinkedHashSet<>(existingList);
                combinedSet.addAll(newList);
                return new ArrayList<>(combinedSet);
            });

            if (persist) {
                try {
                    PersistedObject persistedObject = PersistedObject.persistedObject();
                    gRuleMap.forEach((kName, vList) -> {
                        PersistedList<String> persistedList = PersistedList.persistedStringList();
                        persistedList.addAll(vList);
                        persistedObject.setStringList(kName, persistedList);
                    });
                    putData("data", host, persistedObject);
                } catch (Exception ignored) {
                }
            }

            return gRuleMap;
        });

        String[] splitHost = host.split("\\.");
        String onlyHost = host.split(":")[0];

        String anyHost = (splitHost.length > 2 && !StringProcessor.matchHostIsIp(onlyHost))
                ? StringProcessor.replaceFirstOccurrence(onlyHost, splitHost[0], "*") : "";

        if (!dataMap.containsKey(anyHost) && !anyHost.isEmpty()) {
            dataMap.put(anyHost, new HashMap<>());
        }

        if (!dataMap.containsKey("*")) {
            dataMap.put("*", new HashMap<>());
        }
    }

    @Override
    public void putEmptyHost(String host) {
        dataMap.put(host, new HashMap<>());
    }

    @Override
    public void remove(String host) {
        dataMap.remove(host);
    }

    @Override
    public void removeMatching(String hostPattern) {
        dataMap.keySet().parallelStream().forEach(key -> {
            if (StringProcessor.matchesHostPattern(key, hostPattern) || hostPattern.equals("*")) {
                dataMap.remove(key);
            }
        });

        // 删除无用的通配符数据
        Set<String> wildcardKeys = dataMap.keySet().stream()
                .filter(key -> key.startsWith("*."))
                .collect(Collectors.toSet());

        Set<String> existingSuffixes = dataMap.keySet().stream()
                .filter(key -> !key.startsWith("*."))
                .map(key -> {
                    int dotIndex = key.indexOf(".");
                    return dotIndex != -1 ? key.substring(dotIndex) : "";
                })
                .collect(Collectors.toSet());

        Set<String> keysToRemove = wildcardKeys.stream()
                .filter(key -> !existingSuffixes.contains(key.substring(1)))
                .collect(Collectors.toSet());

        keysToRemove.forEach(dataMap::remove);

        if (dataMap.size() == 1 && dataMap.keySet().stream().anyMatch(key -> key.equals("*"))) {
            dataMap.remove("*");
        }
    }

    @Override
    public void clear() {
        dataMap.clear();
    }

    @Override
    public void loadFromPersistence() {
        PersistedList<String> dataIndex = persistence.extensionData().getStringList("data");
        if (dataIndex != null && !dataIndex.isEmpty()) {
            dataIndex.forEach(index -> {
                PersistedObject dataObj = persistence.extensionData().getChildObject(index);
                try {
                    dataObj.stringListKeys().forEach(dataKey ->
                            mergeData(index, dataKey, dataObj.getStringList(dataKey).stream().toList(), false));
                } catch (Exception ignored) {
                }
            });
        }
    }

    private synchronized void putData(String dataType, String dataName, PersistedObject persistedObject) {
        if (persistence.extensionData().getChildObject(dataName) != null) {
            persistence.extensionData().deleteChildObject(dataName);
        }
        persistence.extensionData().setChildObject(dataName, persistedObject);

        saveIndex(dataType, dataName);
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
}
