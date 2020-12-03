package burp.action;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.json.JSONObject;

import burp.file.ReadFile;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.AutomatonMatcher;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.RunAutomaton;
import jregex.Matcher;
import jregex.Pattern;

public class ExtractContent {
	ReadFile rf = new ReadFile();
	public JSONObject matchRegex(byte[] content, String scopeString, String actionString, String configFilePath) {
		JSONObject tabContent = new JSONObject();
		// 正则匹配提取内容
		try {
			String jsonStr = rf.readFileContent(configFilePath);
		    JSONObject jsonObj = new JSONObject(jsonStr);
		    Iterator<String> k = jsonObj.keys();
		    // 遍历json数组
		    while (k.hasNext()) {
		    	String contentString = new String(content, "UTF-8").intern();
		    	String name = k.next(); 
		    	JSONObject jsonObj1 = new JSONObject(jsonObj.get(name).toString());
		    	JSONObject jsonData = new JSONObject();
				String regex = jsonObj1.getString("regex");
				boolean isLoaded = jsonObj1.getBoolean("loaded");
				String scope = jsonObj1.getString("scope");
				String action = jsonObj1.getString("action");
				String color = jsonObj1.getString("color");
				String engine = jsonObj1.getString("engine");
				
				List<String> result = new ArrayList<String>();
				
				if(isLoaded && (scope.equals(scopeString) || scope.equals("any")) && (action.equals(actionString) || action.equals("any"))) {
					if (engine.equals("nfa")) {
						Pattern pattern = new Pattern(regex);
						Matcher matcher = pattern.matcher(contentString);
						while (matcher.find()) {
							// 添加匹配数据至list
							// 强制用户使用()包裹正则
							result.add(matcher.group(1));
						}
					} else {
						RegExp regexpr = new RegExp(regex);
						Automaton auto = regexpr.toAutomaton();
				        RunAutomaton runAuto = new RunAutomaton(auto, true);
				        AutomatonMatcher autoMatcher = runAuto.newMatcher(contentString);
				        while (autoMatcher.find()) {
							// 添加匹配数据至list
							// 强制用户使用()包裹正则
							result.add(autoMatcher.group());
						}
					}

					// 去除重复内容
					HashSet tmpList = new HashSet(result);
					result.clear();
					result.addAll(tmpList);
					
					if (!result.isEmpty()) {
						jsonData.put("color", color);
						jsonData.put("data", String.join("\n", result));
						jsonData.put("loaded", isLoaded);
						// 初始化格式
						tabContent.put(name, jsonData);
					}
				}

		    }
		    
		    
		} catch (Exception e) {}
		
		return tabContent;
	}
}
