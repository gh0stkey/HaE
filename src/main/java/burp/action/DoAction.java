package burp.action;

import java.util.Map;
import burp.Config;
import java.util.ArrayList;
import java.util.List;

/*
 * @author EvilChen
 */

public class DoAction {
    public String extractString(Map<String, Map<String, Object>> obj) {
        String[] result = {""};
        obj.keySet().forEach(i->{
            Map<String, Object> tmpMap = obj.get(i);
            String data = tmpMap.get("data").toString();
            String tmpStr = String.format(Config.outputTplString, i, data).intern();
            result[0] += tmpStr;
        });
        return result[0];
    }

    public List<String> highlightList(Map<String, Map<String, Object>> obj) {
        List<String> colorList = new ArrayList<>();
        obj.keySet().forEach(i->{
            Map<String, Object> tmpMap = obj.get(i);
            String color = tmpMap.get("color").toString();
            colorList.add(color);
        });
        return colorList;
    }
}