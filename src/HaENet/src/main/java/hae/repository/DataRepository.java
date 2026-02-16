package hae.repository;

import java.util.List;
import java.util.Map;
import java.util.Set;

public interface DataRepository {
    // 读
    Map<String, List<String>> getByHost(String host);
    Set<String> getAllHosts();
    boolean containsHost(String host);
    boolean isEmpty();
    int size();
    Map<String, Map<String, List<String>>> getAll();

    // 写
    void mergeData(String host, String ruleName, List<String> data, boolean persist);
    void putEmptyHost(String host);
    void remove(String host);
    void removeMatching(String hostPattern);
    void clear();

    // 持久化加载
    void loadFromPersistence();
}
