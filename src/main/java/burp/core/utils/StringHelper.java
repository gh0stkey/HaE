package burp.core.utils;

import java.util.HashMap;
import java.util.Map;

public class StringHelper {
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

    public static String mergeComment(String comment) {
        if (!comment.contains(",")) {
            return comment;
        }

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
}
