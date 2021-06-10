package burp.action;

import java.util.ArrayList;
import java.util.List;

/*
 * @author EvilChen
 */

public class GetColorKey {
    /*
     * 颜色下标获取
     */
    public List<Integer> getColorKeys(List<String> keys, String[] colorArray){
        List<Integer> result = new ArrayList<Integer>();
        int size = colorArray.length;
        // 根据颜色获取下标
        for (int x = 0; x < keys.size(); x++) {
            for (int v = 0; v < size; v++) {
                if (colorArray[v].equals(keys.get(x))) {
                    result.add(v);
                }
            }
        }
        return result;
    }
}
