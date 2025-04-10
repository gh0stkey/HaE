package hae.instances.http.utils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * ClassName: BodySplit
 * Package: hae.instances.http.utils
 * Description:
 *
 * @Author Hypdncy
 * @Create 2025/4/10 16:35
 * @Version 1.0
 */

public class BodySplit {
    public static List<String> splitSmart(String text, int maxBytes) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int currentBytes = 0;

        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            current.append(ch);

            int charBytes = String.valueOf(ch).getBytes(StandardCharsets.UTF_8).length;
            currentBytes += charBytes;

            // 判断是否是分号
            if (ch == ';') {
                if (currentBytes >= maxBytes) {
                    segments.add(current.toString());
                    current.setLength(0);
                    currentBytes = 0;
                }
            }
        }

        // 加入最后一段
        if (!current.isEmpty()) {
            segments.add(current.toString());
        }

        return segments;
    }
}
