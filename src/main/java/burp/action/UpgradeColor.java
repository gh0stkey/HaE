package burp.action;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;

/*
 * @author EvilChen
 */

public class UpgradeColor {
    private String endColor = "";
    /*
     * 颜色升级递归算法
     */
    private String colorUpgrade(List<Integer> colorList, String[] colorArray) {
        int colorSize = colorList.size();
        colorList.sort(Comparator.comparingInt(Integer::intValue));
        int i = 0;
        List<Integer> stack = new ArrayList<Integer>();
        while (i < colorSize) {
            if (stack.isEmpty()) {
                stack.add(colorList.get(i));
                i++;
            } else {
                if (colorList.get(i) != stack.stream().reduce((first, second) -> second).orElse(99999999)) {
                    stack.add(colorList.get(i));
                    i++;
                } else {
                    stack.set(stack.size() - 1, stack.get(stack.size() - 1) - 1);
                    i++;
                }
            }

        }
        // 利用HashSet删除重复元素
        HashSet tmpList = new HashSet(stack);
        if (stack.size() == tmpList.size()) {
            stack.sort(Comparator.comparingInt(Integer::intValue));
            if(stack.get(0).equals(-1)) {
                this.endColor = colorArray[0];
            } else {
                this.endColor = colorArray[stack.get(0)];
            }
        } else {
            this.colorUpgrade(stack, colorArray);
        }
        return "";
    }

    public String getEndColor(List<Integer> colorList, String[] colorArray) {
        colorUpgrade(colorList, colorArray);
        return endColor;
    }
}
