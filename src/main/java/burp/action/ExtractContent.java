package burp.action;

import java.nio.charset.StandardCharsets;
import java.util.*;

import burp.Config;
import burp.yaml.LoadConfig;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.AutomatonMatcher;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.RunAutomaton;
import jregex.Matcher;
import jregex.Pattern;

/*
 * @author EvilChen
 */

public class ExtractContent {

    public Map<String, Map<String, Object>> matchRegex(byte[] content, String headers, byte[] body, String scopeString) {
        Map<String, Map<String, Object>> map = new HashMap<>(); // 最终返回的结果
        Config.ruleConfig.keySet().forEach(i -> {
            String matchContent = "";
            for (Object[] objects : Config.ruleConfig.get(i)) {
                // 遍历获取规则
                List<String> result = new ArrayList<>();
                Map<String, Object> tmpMap = new HashMap<>();

                String name = objects[1].toString();
                boolean loaded = (Boolean) objects[0];
                String regex = objects[2].toString();
                String color = objects[3].toString();
                String scope = objects[4].toString();
                String engine = objects[5].toString();
                // 判断规则是否开启与作用域
                if (loaded && (scope.contains(scopeString) || "any".equals(scope))) {
                    switch (scope) {
                        case "any":
                        case "request":
                        case "response":
                            matchContent = new String(content, StandardCharsets.UTF_8).intern();
                            break;
                        case "request header":
                        case "response header":
                            matchContent = headers;
                            break;
                        case "request body":
                        case "response body":
                            matchContent = new String(body, StandardCharsets.UTF_8).intern();
                            break;
                        default:
                            break;
                    }

                    if ("nfa".equals(engine)) {
                        Pattern pattern = new Pattern(regex);
                        Matcher matcher = pattern.matcher(matchContent);
                        while (matcher.find()) {
                            // 添加匹配数据至list
                            // 强制用户使用()包裹正则
                            result.add(matcher.group(1));
                        }
                    } else {
                        RegExp regexp = new RegExp(regex);
                        Automaton auto = regexp.toAutomaton();
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
