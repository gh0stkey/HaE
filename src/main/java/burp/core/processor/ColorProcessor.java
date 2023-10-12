package burp.core.processor;

import burp.config.ConfigEntry;

import java.util.*;

/**
 * @author EvilChen
 */

public class ColorProcessor {
    private String finalColor = "";

    public List<Integer> retrieveColorIndices(List<String> colors){
        List<Integer> indices = new ArrayList<>();
        String[] colorArray = ConfigEntry.colorArray;
        int size = colorArray.length;

        for (String color : colors) {
            for (int i = 0; i < size; i++) {
                if (colorArray[i].equals(color)) {
                    indices.add(i);
                }
            }
        }
        return indices;
    }

    /**
     * 颜色升级递归算法
     */
    private void upgradeColors(List<Integer> colorList) {
        int colorSize = colorList.size();
        String[] colorArray = ConfigEntry.colorArray;
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
                this.finalColor = colorArray[0];
            } else {
                this.finalColor = colorArray[stack.get(0)];
            }
        } else {
            this.upgradeColors(stack);
        }
    }

    public String retrieveFinalColor(List<Integer> colorList) {
        upgradeColors(colorList);
        return finalColor;
    }
}
