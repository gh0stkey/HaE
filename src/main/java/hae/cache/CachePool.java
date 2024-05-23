package hae.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.Map;
import java.util.concurrent.TimeUnit;

public class CachePool {
    private static final int MAX_SIZE = 100000;
    private static final int EXPIRE_DURATION = 5;

    private static final Cache<String, Map<String, Map<String, Object>>> cache =
            Caffeine.newBuilder()
                    .maximumSize(MAX_SIZE)
                    .expireAfterWrite(EXPIRE_DURATION, TimeUnit.HOURS)
                    .build();

    public static void put(String key, Map<String, Map<String, Object>> value) {
        cache.put(key, value);
    }

    public static Map<String, Map<String, Object>> get(String key) {
        return cache.getIfPresent(key);
    }

    public static void remove(String key) {
        cache.invalidate(key);
    }

    public static void clear() {
        cache.invalidateAll();
    }
}