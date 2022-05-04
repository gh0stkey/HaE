package burp.action;

import burp.Config;

import java.util.*;

/**
 * @author EvilChen
 */

public class UpgradeColor {
    private String endColor = "";
    /**
     * 颜色升级递归算法
     */
    private void colorUpgrade(List<Integer> colorList) {
        int colorSize = colorList.size();
        String[] colorArray = Config.colorArray;
        colorList.sort(Comparator.comparingInt(Integer::intValue));
        int i = 0;
        List<Integer> stack = new ArrayList<>();
        while (i < colorSize) {
            if (stack.isEmpty()) {
                stack.add(colorList.get(i));
            } else {
                if (!Objects.equals(colorList.get(i), stack.stream().reduce((first, second) -> second).orElse(99999999))) {
                    stack.add(colorList.get(i));
                } else {
                    stack.set(stack.size() - 1, stack.get(stack.size() - 1) - 1);
                }
            }
            i++;
        }
        // 利用HashSet删除重复元素
        HashSet tmpList = new HashSet(stack);
        if (stack.size() == tmpList.size()) {
            stack.sort(Comparator.comparingInt(Integer::intValue));
            if(stack.get(0) < 0) {
                this.endColor = colorArray[0];
            } else {
                this.endColor = colorArray[stack.get(0)];
            }
        } else {
            this.colorUpgrade(stack);
        }
    }

    public String getEndColor(List<Integer> colorList) {
        colorUpgrade(colorList);
        return endColor;
    }
}
