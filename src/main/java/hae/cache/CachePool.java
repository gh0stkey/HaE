package hae.cache;

import java.util.*;

public class CachePool {
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