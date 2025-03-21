package hae.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class DataQueryCache {
    private static final int MAX_SIZE = 1000;
    private static final int EXPIRE_DURATION = 30;

    private static final Cache<String, Map<String, List<String>>> hostQueryCache =
            Caffeine.newBuilder()
                    .maximumSize(MAX_SIZE)
                    .expireAfterWrite(EXPIRE_DURATION, TimeUnit.MINUTES)
                    .build();

    private static final Cache<String, List<String>> hostFilterCache =
            Caffeine.newBuilder()
                    .maximumSize(MAX_SIZE)
                    .expireAfterWrite(EXPIRE_DURATION, TimeUnit.MINUTES)
                    .build();

    public static void putHostQueryResult(String host, Map<String, List<String>> result) {
        hostQueryCache.put(host, result);
    }

    public static Map<String, List<String>> getHostQueryResult(String host) {
        return hostQueryCache.getIfPresent(host);
    }

    public static void putHostFilterResult(String input, List<String> result) {
        hostFilterCache.put(input, result);
    }

    public static List<String> getHostFilterResult(String input) {
        return hostFilterCache.getIfPresent(input);
    }

    public static void clearCache() {
        hostQueryCache.invalidateAll();
        hostFilterCache.invalidateAll();
    }
}