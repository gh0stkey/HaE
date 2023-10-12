package burp.core;

import java.util.HashMap;
import java.util.Map;

/**
 * @author EvilChen
 */

public class GlobalCachePool {
    // 用于缓存匹配结果，以请求/响应的MD5 Hash作为索引
    private static final Map<String, Map<String, Map<String, Object>>> cache = new HashMap<>();

    public static void addToCache(String key, Map<String, Map<String, Object>> value) {
        cache.put(key, value);
    }

    public static Map<String, Map<String, Object>> getFromCache(String key) {
        return cache.get(key);
    }

    public static void removeFromCache(String key) {
        cache.remove(key);
    }

}