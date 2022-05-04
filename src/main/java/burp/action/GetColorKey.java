package burp.action;

import burp.Config;
import java.util.ArrayList;
import java.util.List;

/**
 * @author EvilChen
 */

public class GetColorKey {
    /**
     * 颜色下标获取
     */
    public List<Integer> getColorKeys(List<String> keys){
        List<Integer> result = new ArrayList<>();
        String[] colorArray = Config.colorArray;
        int size = colorArray.length;
        // 根据颜色获取下标
        for (String key : keys) {
            for (int v = 0; v < size; v++) {
                if (colorArray[v].equals(key)) {
                    result.add(v);
                }
            }
        }
        return result;
    }
}
