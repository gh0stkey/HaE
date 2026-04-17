package hae.component.board.message;

import hae.utils.string.StringProcessor;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class MessageDeduplicator {

    public boolean isDuplicate(
        List<MessageEntry> log,
        String url,
        String comment,
        String color,
        String dataFingerprint
    ) {
        if (log.isEmpty()) {
            return false;
        }

        String host = StringProcessor.getHostByUrl(url);

        for (MessageEntry entry : log) {
            if (host.equals(StringProcessor.getHostByUrl(entry.getUrl()))) {
                if (
                    isRequestDuplicate(
                        url,
                        entry.getUrl(),
                        comment,
                        entry.getComment(),
                        color,
                        entry.getColor(),
                        dataFingerprint,
                        entry.getDataFingerprint()
                    )
                ) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isRequestDuplicate(
        String newUrl,
        String existingUrl,
        String newComment,
        String existingComment,
        String newColor,
        String existingColor,
        String newFingerprint,
        String existingFingerprint
    ) {
        try {
            // URL匹配
            String normalizedNewUrl = normalizeUrl(newUrl);
            String normalizedExistingUrl = normalizeUrl(existingUrl);
            boolean urlMatch = normalizedNewUrl.equals(normalizedExistingUrl);

            if (!urlMatch) {
                return false;
            }

            // 注释和颜色匹配（同规则、同数量、同颜色）
            boolean metadataMatch =
                areCommentsEqual(newComment, existingComment) &&
                newColor.equals(existingColor);

            if (!metadataMatch) {
                return false;
            }

            // 基于匹配数据指纹判断是否重复
            if (
                newFingerprint != null &&
                !newFingerprint.isEmpty() &&
                existingFingerprint != null &&
                !existingFingerprint.isEmpty()
            ) {
                return newFingerprint.equals(existingFingerprint);
            }

            // 指纹不可用时，认为不是重复
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private String normalizeUrl(String url) {
        if (url == null) {
            return "";
        }

        String normalized = url.trim().toLowerCase();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        int protocolEnd = normalized.indexOf("://");
        if (protocolEnd >= 0) {
            String protocol = normalized.substring(0, protocolEnd + 3);
            String rest = normalized
                .substring(protocolEnd + 3)
                .replaceAll("//+", "/");
            return protocol + rest;
        }

        return normalized.replaceAll("//+", "/");
    }

    private boolean areCommentsEqual(String comment1, String comment2) {
        if (comment1 == null || comment2 == null) {
            return false;
        }

        try {
            Set<String> rules1 = new TreeSet<>(
                Arrays.asList(comment1.split(", "))
            );
            Set<String> rules2 = new TreeSet<>(
                Arrays.asList(comment2.split(", "))
            );
            return rules1.equals(rules2);
        } catch (Exception e) {
            return false;
        }
    }
}
