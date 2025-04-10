package hae.instances.http.utils;

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
        List<String> result = new ArrayList<>();
        StringBuilder currentPart = new StringBuilder();
        StringBuilder tempPart = new StringBuilder();

        // 遍历整个输入字符串
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            tempPart.append(c);

            // 如果遇到分号 ';'，判断是否拼接到达最小长度
            if (c == ';') {
                // 将tempPart拼接到currentPart中
                if (currentPart.length() + tempPart.length() >= maxBytes) {
                    currentPart.append(tempPart);
                    result.add(currentPart.toString());
                    currentPart.setLength(0);  // 清空currentPart准备下一个部分
                } else {
                    currentPart.append(tempPart.toString());
                }
                tempPart.setLength(0);  // 清空tempPart，准备下一个部分
            }
        }

        // 如果还有未处理的部分，添加到结果中
        if (!tempPart.isEmpty()) {
            currentPart.append(tempPart);
        }

        // 最后将剩余部分添加到结果中
        if (!currentPart.isEmpty()) {
            result.add(currentPart.toString());
        }

        return result;
    }
}
