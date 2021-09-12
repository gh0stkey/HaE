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

    public List<List<String>> highlightAndComment(Map<String, Map<String, Object>> obj) {
        List<String> colorList = new ArrayList<>();
        List<String> commentList = new ArrayList<>();
        List<List<String>> result = new ArrayList<>();
        obj.keySet().forEach(i->{
            Map<String, Object> tmpMap = obj.get(i);
            String color = tmpMap.get("color").toString();
            colorList.add(color);
            commentList.add(i);
        });
        result.add(colorList);
        result.add(commentList);
        return result;
    }
}