package burp.action;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.json.JSONObject;

import burp.Config;

public class DoAction {
	public String extractString(JSONObject jsonObj) {
		String result = "";
		Iterator<String> k = jsonObj.keys();
		while (k.hasNext()) {
			String name = k.next();
			JSONObject jsonObj1 = new JSONObject(jsonObj.get(name).toString());
			String tmpStr = String.format(Config.outputTplString, name, jsonObj1.getString("data")).intern();
			result += tmpStr;
		}
		return result;
	}
	
	public List<String> highlightList(JSONObject jsonObj) {
		List<String> colorList = new ArrayList<String>();
        Iterator<String> k = jsonObj.keys();
        while (k.hasNext()) {
            String name = k.next();
            JSONObject jsonObj2 = new JSONObject(jsonObj.get(name).toString());
            colorList.add(jsonObj2.getString("color"));
        }
		return colorList;
	}
}
