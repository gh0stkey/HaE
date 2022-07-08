package burp.action;

import java.nio.charset.StandardCharsets;
import java.util.*;
import burp.Config;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.AutomatonMatcher;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.RunAutomaton;
import jregex.Matcher;
import jregex.Pattern;

/**
 * @author EvilChen
 */

public class ExtractContent {

    public Map<String, Map<String, Object>> matchRegex(byte[] content, String headers, byte[] body, String scopeString, String host) {
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
                boolean sensitive = (Boolean) objects[6];
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
                        Pattern pattern;
                        // 判断规则是否大小写敏感
                        if (sensitive) {
                            pattern = new Pattern(regex);
                        } else {
                            pattern = new Pattern(regex, Pattern.IGNORE_CASE);
                        }

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

        // 将提取的数据存放到全局变量中
        if (!host.isEmpty()) {
            map.keySet().forEach(i -> {
                Map<String, Object> tmpMap = map.get(i);
                List<String> dataList = Arrays.asList(tmpMap.get("data").toString().split("\n"));
                // 判断Host是否存在，如存在则进行数据更新，反之则新增数据
                if (Config.globalDataMap.containsKey(host)) {
                    Map<String, List<String>> gRuleMap = Config.globalDataMap.get(host);
                    // 判断匹配规则是否存在（逻辑同Host判断）
                    if (gRuleMap.containsKey(i)) {
                        List<String> gDataList = gRuleMap.get(i);
                        List<String> mergeDataList = new ArrayList<>();
                        // 合并两个List
                        mergeDataList.addAll(gDataList);
                        mergeDataList.addAll(dataList);
                        // 去重操作
                        HashSet tmpList = new HashSet(mergeDataList);
                        mergeDataList.clear();
                        mergeDataList.addAll(tmpList);
                        // 替换操作
                        gRuleMap.replace(i, gDataList, mergeDataList);
                    } else {
                        gRuleMap.put(i, dataList);
                    }
                } else {
                    Map<String, List<String>> ruleMap = new HashMap<>();
                    ruleMap.put(i, dataList);
                    Config.globalDataMap.put(host, ruleMap);
                }
            });
        }

        return map;
    }
}
