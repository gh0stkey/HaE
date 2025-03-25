package hae.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.Map;

public class MessageCache {
    private static final Cache<String, Map<String, Map<String, Object>>> cache =
            Caffeine.newBuilder()
                    .build();

    public static void put(String key, Map<String, Map<String, Object>> value) {
        cache.put(key, value);
    }

    public static Map<String, Map<String, Object>> get(String key) {
        return cache.getIfPresent(key);
    }

    public static void clear() {
        cache.invalidateAll();
    }
}