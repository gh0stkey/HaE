package burp.action;

import java.io.UnsupportedEncodingException;
import java.util.*;

import dk.brics.automaton.Automaton;
import dk.brics.automaton.AutomatonMatcher;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.RunAutomaton;
import jregex.Matcher;
import jregex.Pattern;

import burp.yaml.LoadRule;
import burp.yaml.LoadConfigFile;

/*
 * @author EvilChen
 */

public class ExtractContent {
    private LoadConfigFile lcf = new LoadConfigFile();
    private LoadRule lr = new LoadRule(lcf.getConfigPath());

    public Map<String, Map<String, Object>> matchRegex(byte[] content, String headers, byte[] body, String scopeString) {
        Map<String, Map<String, Object>> map = new HashMap<>(); // 最终返回的结果
        Map<String,Object[][]> rules = lr.getConfig();
        rules.keySet().forEach(i -> {
            String matchContent = "";
            for (Object[] objects : rules.get(i)) {
                // 遍历获取规则
                List<String> result = new ArrayList<String>();
                Map<String, Object> tmpMap = new HashMap<>();

                String name = objects[1].toString();
                boolean loaded = (Boolean) objects[0];
                String regex = objects[2].toString();
                String color = objects[3].toString();
                String scope = objects[4].toString();
                String engine = objects[5].toString();
                // 判断规则是否开启与作用域
                if (loaded && (scopeString.contains(scope) || scope.equals("any"))) {
                    switch (scope) {
                        case "any":
                        case "request":
                        case "response":
                            try {
                                matchContent = new String(content, "UTF-8").intern();
                            } catch (UnsupportedEncodingException e) {
                                e.printStackTrace();
                            }
                            break;
                        case "request header":
                        case "response header":
                            matchContent = headers;
                            break;
                        case "request body":
                        case "response body":
                            try {
                                matchContent = new String(body, "UTF-8").intern();
                            } catch (UnsupportedEncodingException e) {
                                e.printStackTrace();
                            }
                            break;
                    }

                    if (engine.equals("nfa")) {
                        Pattern pattern = new Pattern(regex);
                        Matcher matcher = pattern.matcher(matchContent);
                        while (matcher.find()) {
                            // 添加匹配数据至list
                            // 强制用户使用()包裹正则
                            result.add(matcher.group(1));
                        }
                    } else {
                        RegExp regexpr = new RegExp(regex);
                        Automaton auto = regexpr.toAutomaton();
                        RunAutomaton runAuto = new RunAutomaton(auto, true);
                        AutomatonMatcher autoMatcher = runAuto.newMatcher(matchContent);
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
                        tmpMap.put("color", color);
                        tmpMap.put("data", String.join("\n", result));
                        // 初始化格式
                        map.put(name, tmpMap);
                    }
                }
            }
        });

        return map;
    }
}
