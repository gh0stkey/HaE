package hae.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.Persistence;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import hae.repository.RuleRepository;
import hae.utils.rule.model.RuleDefinition;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ValidatorService {
    public static final String SEVERITY_HIGH = "high";
    public static final String SEVERITY_MEDIUM = "medium";
    public static final String SEVERITY_LOW = "low";
    public static final String SEVERITY_NONE = "none";
    public static final String[] SEVERITY_LEVELS = {SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_NONE};
    public static final Map<String, Integer> SEVERITY_RANK = Map.of(
            SEVERITY_HIGH, 0, SEVERITY_MEDIUM, 1, SEVERITY_LOW, 2, SEVERITY_NONE, 3
    );

    private static final int DEFAULT_TIMEOUT = 5000;
    private static final int DEFAULT_BULK = 500;
    private static final Set<String> VALID_TAGS = Set.of(SEVERITY_NONE, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH);

    private static final String SEVERITY_INDEX_KEY = "severity_index";
    private static final String SEVERITY_PREFIX = "sev_";

    private final MontoyaApi api;
    private final RuleRepository ruleRepository;
    private final Persistence persistence;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    // ruleName -> matchValue -> severity
    private final ConcurrentHashMap<String, ConcurrentHashMap<String, String>> severityStore = new ConcurrentHashMap<>();

    // ruleName -> matchValue -> [before, after]
    private static final ConcurrentHashMap<String, ConcurrentHashMap<String, String[]>> contextStore = new ConcurrentHashMap<>();
    // ruleName -> matchValue -> url
    private static final ConcurrentHashMap<String, ConcurrentHashMap<String, String>> urlStore = new ConcurrentHashMap<>();
    private static final int CONTEXT_LENGTH = 50;

    public ValidatorService(MontoyaApi api, RuleRepository ruleRepository) {
        this.api = api;
        this.ruleRepository = ruleRepository;
        this.persistence = api.persistence();
        loadFromPersistence();
    }

    public String getSeverity(String ruleName, String matchValue) {
        ConcurrentHashMap<String, String> ruleMap = severityStore.get(ruleName);
        return ruleMap != null ? ruleMap.get(matchValue) : null;
    }

    public void setSeverity(String ruleName, String matchValue, String severity) {
        severityStore.computeIfAbsent(ruleName, k -> new ConcurrentHashMap<>()).put(matchValue, severity);
    }

    public void revalidateAll(Map<String, List<String>> ruleDataMap, String groupName, Runnable onComplete) {
        executor.submit(() -> {
            try {
                for (Map.Entry<String, List<String>> entry : ruleDataMap.entrySet()) {
                    String ruleName = entry.getKey();
                    RuleDefinition rule = findRule(groupName, ruleName);
                    if (rule != null && rule.getValidator() != null && !rule.getValidator().isEmpty()) {
                        runValidation(rule, groupName, entry.getValue());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("[Validator] Error: " + e.getMessage());
            } finally {
                if (onComplete != null) onComplete.run();
            }
        });
    }

    public void autoValidate(Map<String, List<String>> ruleDataMap, String groupName, Runnable onComplete) {
        Map<String, List<String>> needValidation = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : ruleDataMap.entrySet()) {
            String ruleName = entry.getKey();
            ConcurrentHashMap<String, String> ruleMap = severityStore.get(ruleName);
            List<String> unseen = new ArrayList<>();
            for (String match : entry.getValue()) {
                if (ruleMap == null || !ruleMap.containsKey(match)) {
                    unseen.add(match);
                }
            }
            if (!unseen.isEmpty()) {
                needValidation.put(ruleName, unseen);
            }
        }
        if (needValidation.isEmpty()) {
            if (onComplete != null) onComplete.run();
            return;
        }
        revalidateAll(needValidation, groupName, onComplete);
    }

    private void runValidation(RuleDefinition rule, String group, List<String> matches) {
        if (matches.isEmpty()) return;

        int timeout = rule.getValidatorTimeout() > 0 ? rule.getValidatorTimeout() : DEFAULT_TIMEOUT;
        int bulk = rule.getValidatorBulk() > 0 ? rule.getValidatorBulk() : DEFAULT_BULK;

        ConcurrentHashMap<String, String> ruleStore = severityStore.computeIfAbsent(rule.getName(), k -> new ConcurrentHashMap<>());

        for (int offset = 0; offset < matches.size(); offset += bulk) {
            List<String> batch = matches.subList(offset, Math.min(offset + bulk, matches.size()));

            String inputJson = buildInputJson(rule, group, batch);
            String output = executeCommand(rule.getValidator(), inputJson, timeout);
            if (output == null) continue;

            Map<Integer, String> resultMap = parseOutput(output);
            for (int i = 0; i < batch.size(); i++) {
                String severity = resultMap.getOrDefault(i, SEVERITY_NONE);
                ruleStore.put(batch.get(i), severity);
            }
        }

        api.logging().logToOutput(String.format("[Validator] %s: validated %d matches", rule.getName(), matches.size()));
        persistRule(rule.getName());
    }

    private RuleDefinition findRule(String groupHint, String ruleName) {
        if (groupHint != null) {
            List<RuleDefinition> rules = ruleRepository.getRulesByGroup(groupHint);
            if (rules != null) {
                for (RuleDefinition r : rules) {
                    if (r.getName().equals(ruleName)) return r;
                }
            }
        }
        for (String g : ruleRepository.getAllGroupNames()) {
            List<RuleDefinition> rules = ruleRepository.getRulesByGroup(g);
            if (rules != null) {
                for (RuleDefinition r : rules) {
                    if (r.getName().equals(ruleName)) return r;
                }
            }
        }
        return null;
    }

    public static void putContext(String ruleName, String matchValue, String matchContent) {
        ConcurrentHashMap<String, String[]> ruleCtx = contextStore.computeIfAbsent(ruleName, k -> new ConcurrentHashMap<>());
        if (ruleCtx.containsKey(matchValue)) return;
        int pos = matchContent.indexOf(matchValue);
        if (pos < 0) return;
        String before = matchContent.substring(Math.max(0, pos - CONTEXT_LENGTH), pos);
        String after = matchContent.substring(
                Math.min(pos + matchValue.length(), matchContent.length()),
                Math.min(pos + matchValue.length() + CONTEXT_LENGTH, matchContent.length()));
        ruleCtx.putIfAbsent(matchValue, new String[]{before, after});
    }

    public static void putUrl(String ruleName, String matchValue, String url) {
        ConcurrentHashMap<String, String> ruleUrls = urlStore.computeIfAbsent(ruleName, k -> new ConcurrentHashMap<>());
        ruleUrls.putIfAbsent(matchValue, url);
    }

    public void clear() {
        severityStore.clear();
        contextStore.clear();
        urlStore.clear();
    }

    public void dispose() {
        executor.shutdownNow();
        persistAll();
        severityStore.clear();
        contextStore.clear();
        urlStore.clear();
    }

    public static int compareBySeverity(String a, String b) {
        int ra = SEVERITY_RANK.getOrDefault(a, 3);
        int rb = SEVERITY_RANK.getOrDefault(b, 3);
        return Integer.compare(ra, rb);
    }

    private void loadFromPersistence() {
        try {
            PersistedList<String> index = persistence.extensionData().getStringList(SEVERITY_INDEX_KEY);
            if (index == null || index.isEmpty()) return;

            for (String ruleName : index) {
                PersistedList<String> entries = persistence.extensionData().getStringList(SEVERITY_PREFIX + ruleName);
                if (entries == null) continue;
                ConcurrentHashMap<String, String> ruleMap = severityStore.computeIfAbsent(ruleName, k -> new ConcurrentHashMap<>());
                for (String entry : entries) {
                    int sep = entry.lastIndexOf('\t');
                    if (sep > 0 && sep < entry.length() - 1) {
                        String matchValue = entry.substring(0, sep);
                        String severity = entry.substring(sep + 1);
                        if (VALID_TAGS.contains(severity)) {
                            ruleMap.put(matchValue, severity);
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Validator] Failed to load severity: " + e.getMessage());
        }
    }

    public synchronized void persistRule(String ruleName) {
        try {
            ConcurrentHashMap<String, String> ruleMap = severityStore.get(ruleName);
            if (ruleMap == null || ruleMap.isEmpty()) return;

            PersistedList<String> entries = PersistedList.persistedStringList();
            for (Map.Entry<String, String> e : ruleMap.entrySet()) {
                entries.add(e.getKey() + "\t" + e.getValue());
            }
            persistence.extensionData().setStringList(SEVERITY_PREFIX + ruleName, entries);

            // Update index
            PersistedList<String> index = persistence.extensionData().getStringList(SEVERITY_INDEX_KEY);
            if (index == null) {
                index = PersistedList.persistedStringList();
            }
            if (!index.contains(ruleName)) {
                index.add(ruleName);
                persistence.extensionData().setStringList(SEVERITY_INDEX_KEY, index);
            }
        } catch (Exception e) {
            api.logging().logToError("[Validator] Failed to persist severity for " + ruleName + ": " + e.getMessage());
        }
    }

    private void persistAll() {
        for (String ruleName : severityStore.keySet()) {
            persistRule(ruleName);
        }
    }

    private static final Gson GSON = new Gson();

    private static String buildInputJson(RuleDefinition rule, String group, List<String> matches) {
        JsonObject root = new JsonObject();

        JsonObject ruleObj = new JsonObject();
        ruleObj.addProperty("name", rule.getName());
        ruleObj.addProperty("regex", rule.getFirstRegex());
        ruleObj.addProperty("group", group);
        root.add("rule", ruleObj);

        JsonArray items = getJsonElements(rule.getName(), matches);
        root.add("items", items);

        return GSON.toJson(root);
    }

    private static @NonNull JsonArray getJsonElements(String ruleName, List<String> matches) {
        ConcurrentHashMap<String, String[]> ruleCtx = contextStore.get(ruleName);
        ConcurrentHashMap<String, String> ruleUrls = urlStore.get(ruleName);
        JsonArray items = new JsonArray();
        for (int i = 0; i < matches.size(); i++) {
            JsonObject item = new JsonObject();
            item.addProperty("index", i);

            JsonObject data = new JsonObject();
            data.addProperty("match", matches.get(i));
            String url = ruleUrls != null ? ruleUrls.get(matches.get(i)) : null;
            data.addProperty("url", url != null ? url : "");
            JsonObject context = new JsonObject();
            String[] ctx = ruleCtx != null ? ruleCtx.get(matches.get(i)) : null;
            context.addProperty("before", ctx != null ? ctx[0] : "");
            context.addProperty("after", ctx != null ? ctx[1] : "");
            data.add("context", context);

            item.add("data", data);
            items.add(item);
        }
        return items;
    }

    private static String executeCommand(String command, String input, long timeout) {
        try {
            String osName = System.getProperty("os.name", "").toLowerCase();
            String[] cmd = osName.contains("win")
                    ? new String[]{"cmd", "/c", command}
                    : new String[]{"/bin/sh", "-c", command};
            Process process = new ProcessBuilder(cmd).start();

            Thread writer = new Thread(() -> {
                try (OutputStream os = process.getOutputStream()) {
                    os.write(input.getBytes(StandardCharsets.UTF_8));
                } catch (IOException ignored) {
                }
            });
            writer.start();

            StringBuilder stdout = new StringBuilder();
            Thread reader = new Thread(() -> {
                try (InputStream is = process.getInputStream()) {
                    stdout.append(new String(is.readAllBytes(), StandardCharsets.UTF_8));
                } catch (IOException ignored) {
                }
            });
            reader.start();

            boolean finished = process.waitFor(timeout, TimeUnit.MILLISECONDS);
            if (!finished) {
                process.destroyForcibly();
                writer.join(1000);
                reader.join(1000);
                return null;
            }

            writer.join(1000);
            reader.join(1000);
            return process.exitValue() == 0 ? stdout.toString().trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static Map<Integer, String> parseOutput(String output) {
        Map<Integer, String> severityMap = new HashMap<>();
        try {
            JsonObject parsed = GSON.fromJson(output, JsonObject.class);
            if (parsed == null || !parsed.has("results")) return severityMap;

            JsonArray results = parsed.getAsJsonArray("results");
            for (int i = 0; i < results.size(); i++) {
                JsonObject r = results.get(i).getAsJsonObject();
                int index = r.get("index").getAsInt();
                String tags = r.get("tags").getAsString();
                if (VALID_TAGS.contains(tags)) {
                    severityMap.put(index, tags);
                }
            }
        } catch (Exception ignored) {
        }
        return severityMap;
    }
}
