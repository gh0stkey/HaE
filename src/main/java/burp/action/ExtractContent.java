package burp.action;

import burp.BurpExtender;
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
            for (Object[] objects : Config.ruleConfig.get(i)) {
                // 多线程执行，一定程度上减少阻塞现象
                Thread t = new Thread(() -> {
                    String matchContent = "";
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
                    if (loaded && (scope.contains(scopeString) || scope.contains("any"))) {
                        switch (scope) {
                            case "any":
                            case "request":
                            case "response":
                                matchContent = new String(content, StandardCharsets.UTF_8).intern();
                                break;
                            case "any header":
                            case "request header":
                            case "response header":
                                matchContent = headers;
                                break;
                            case "any body":
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

                        String nameAndSize = String.format("%s (%s)", name, result.size());
                        if (!result.isEmpty()) {
                            tmpMap.put("color", color);
                            String dataStr = String.join("\n", result);
                            tmpMap.put("data", dataStr);

                            // 添加到全局变量中，便于Databoard检索
                            if (!host.isEmpty()) {
                                String[] splitHost = host.split("\\.");
                                String anyHost = (splitHost.length > 2 && !host.matches("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")) ? host.replace(splitHost[0], "*") : "";
                                List<String> dataList = Arrays.asList(dataStr.split("\n"));
                                if (Config.globalDataMap.containsKey(host)) {
                                    Map<String, List<String>> gRuleMap = new HashMap<>(Config.globalDataMap.get(host));
                                    if (gRuleMap.containsKey(name)) {
                                        List<String> gDataList = gRuleMap.get(name);
                                        gDataList.addAll(dataList);
                                        gDataList = new ArrayList<>(new HashSet<>(gDataList));
                                        gRuleMap.replace(name, gDataList);
                                    } else {
                                        gRuleMap.put(name, dataList);
                                    }
                                    Config.globalDataMap.remove(host);
                                    Config.globalDataMap.put(host, gRuleMap);
                                } else {
                                    Map<String, List<String>> ruleMap = new HashMap<>();
                                    ruleMap.put(name, dataList);
                                    // 添加单一Host
                                    Config.globalDataMap.put(host, ruleMap);
                                }

                                if (!Config.globalDataMap.containsKey(anyHost) && anyHost.length() > 0) {
                                    // 添加通配符Host，实际数据从查询哪里将所有数据提取
                                    Config.globalDataMap.put(anyHost, new HashMap<>());
                                } else if (!Config.globalDataMap.containsKey("*")) {
                                    // 添加通配符全匹配，同上
                                    Config.globalDataMap.put("*", new HashMap<>());
                                }
                            }

                            map.put(nameAndSize, tmpMap);

                        }
                    }
                });
                t.start();
                try {
                    t.join();
                } catch (InterruptedException e) {
                    BurpExtender.stdout.println(e);
                }


            }
        });
        return map;
    }
}
