package hae.utils.string;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class StringProcessor {
    public static String replaceFirstOccurrence(String original, String find, String replace) {
        int index = original.indexOf(find);
        if (index != -1) {
            return original.substring(0, index) + replace + original.substring(index + find.length());
        }
        return original;
    }

    public static boolean matchFromEnd(String input, String pattern) {
        int inputLength = input.length();
        int patternLength = pattern.length();

        int inputIndex = inputLength - 1;
        int patternIndex = patternLength - 1;

        while (inputIndex >= 0 && patternIndex >= 0) {
            if (input.charAt(inputIndex) != pattern.charAt(patternIndex)) {
                return false;
            }
            inputIndex--;
            patternIndex--;
        }

        // 如果patternIndex为-1，表示pattern字符串已经完全匹配
        return patternIndex == -1;
    }

    public static String extractHostname(String hostWithPort) {
        if (hostWithPort == null || hostWithPort.isEmpty()) {
            return "";
        }
        int colonIndex = hostWithPort.indexOf(":");
        if (colonIndex != -1) {
            return hostWithPort.substring(0, colonIndex);
        } else {
            return hostWithPort;
        }
    }

    public static boolean matchesHostPattern(String host, String selectedHost) {
        String hostname = StringProcessor.extractHostname(host);
        String hostPattern = selectedHost.replace("*.", "");
        boolean matchesDirectly = selectedHost.equals("*") || host.equals(selectedHost);
        boolean matchesPattern = !host.contains("*") &&
                (hostPattern.equals(selectedHost) ?
                        StringProcessor.matchFromEnd(host, hostPattern) :
                        StringProcessor.matchFromEnd(hostname, hostPattern));
        return matchesDirectly || matchesPattern;
    }

    public static String getRandomUUID() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString();
    }

    public static String mergeComment(String comment) {
        if (!comment.contains(",")) {
            return comment;
        }

        Map<String, Integer> itemCounts = getStringIntegerMap(comment);

        StringBuilder mergedItems = new StringBuilder();

        for (Map.Entry<String, Integer> entry : itemCounts.entrySet()) {
            String itemName = entry.getKey();
            int count = entry.getValue();
            if (count != 0) {
                mergedItems.append(itemName).append(" (").append(count).append("), ");
            }
        }

        return mergedItems.substring(0, mergedItems.length() - 2);
    }

    public static String getHostByUrl(String url) {
        String host = "";

        try {
            URL u = new URL(url);
            int port = u.getPort();
            if (port == -1) {
                host = u.getHost();
            } else {
                host = String.format("%s:%s", u.getHost(), port);
            }
        } catch (Exception ignored) {
        }

        return host;
    }

    public static boolean matchHostIsIp(String host) {
        return host.matches("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    }

    private static Map<String, Integer> getStringIntegerMap(String comment) {
        Map<String, Integer> itemCounts = new HashMap<>();
        String[] items = comment.split(", ");

        for (String item : items) {
            if (item.contains("(") && item.contains(")")) {
                int openParenIndex = item.lastIndexOf("(");
                int closeParenIndex = item.lastIndexOf(")");
                String itemName = item.substring(0, openParenIndex).trim();
                int count = Integer.parseInt(item.substring(openParenIndex + 1, closeParenIndex).trim());
                itemCounts.put(itemName, itemCounts.getOrDefault(itemName, 0) + count);
            } else {
                itemCounts.put(item, 0);
            }
        }

        return itemCounts;
    }
}

