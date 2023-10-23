package burp.core.processor;

import burp.BurpExtender;
import burp.core.GlobalCachePool;
import burp.core.utils.HashCalculator;
import burp.core.utils.MatchTool;
import burp.config.ConfigEntry;
import burp.core.utils.StringHelper;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.AutomatonMatcher;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.RunAutomaton;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import jregex.Matcher;
import jregex.Pattern;

/**
 * @author EvilChen
 */

public class DataProcessingUnit {
    public Map<String, String> extractDataFromMap(Map<String, Map<String, Object>> inputData) {
        Map<String, String> extractedData = new HashMap<>();
        inputData.keySet().forEach(key -> {
            Map<String, Object> tempMap = inputData.get(key);
            String data = tempMap.get("data").toString();
            extractedData.put(key, data);
        });
        return extractedData;
    }

    public List<List<String>> extractColorsAndComments(Map<String, Map<String, Object>> inputData) {
        List<String> colorList = new ArrayList<>();
        List<String> commentList = new ArrayList<>();
        inputData.keySet().forEach(key -> {
            Map<String, Object> tempMap = inputData.get(key);
            String color = tempMap.get("color").toString();
            colorList.add(color);
            commentList.add(key);
        });
        List<List<String>> result = new ArrayList<>();
        result.add(colorList);
        result.add(commentList);
        return result;
    }

    public Map<String, Map<String, Object>> matchContentByRegex(byte[] content, String headers, byte[] body, String scopeString, String host)
            throws NoSuchAlgorithmException {
        // 先从缓存池里判断是否有已经匹配好的结果
        String messageIndex = HashCalculator.calculateHash(content);
        Map<String, Map<String, Object>> map = GlobalCachePool.getFromCache(messageIndex);
        if (map != null) {
            return map;
        } else {
            // 最终返回的结果
            Map<String, Map<String, Object>> finalMap = new HashMap<>();
            ConfigEntry.globalRules.keySet().forEach(i -> {
                for (Object[] objects : ConfigEntry.globalRules.get(i)) {
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
                                    matchContent = new String(content, StandardCharsets.UTF_8);
                                    break;
                                case "any header":
                                case "request header":
                                case "response header":
                                    matchContent = headers;
                                    break;
                                case "any body":
                                case "request body":
                                case "response body":
                                    matchContent = new String(body, StandardCharsets.UTF_8);
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
                                finalMap.put(nameAndSize, tmpMap);
                                // 添加到全局变量中，便于Databoard检索
                                if (!Objects.equals(host, "")) {
                                    List<String> dataList = Arrays.asList(dataStr.split("\n"));
                                    if (ConfigEntry.globalDataMap.containsKey(host)) {
                                        Map<String, List<String>> gRuleMap = new HashMap<>(ConfigEntry.globalDataMap.get(host));
                                        if (gRuleMap.containsKey(name)) {
                                            // gDataList为不可变列表，因此需要重新创建一个列表以便于使用addAll方法
                                            List<String> gDataList = gRuleMap.get(name);
                                            List<String> newDataList = new ArrayList<>(gDataList);
                                            newDataList.addAll(dataList);
                                            newDataList = new ArrayList<>(new HashSet<>(newDataList));
                                            gRuleMap.remove(name);
                                            gRuleMap.put(name, newDataList);
                                        } else {
                                            gRuleMap.put(name, dataList);
                                        }
                                        ConfigEntry.globalDataMap.remove(host);
                                        ConfigEntry.globalDataMap.put(host, gRuleMap);
                                    } else {
                                        Map<String, List<String>> ruleMap = new HashMap<>();
                                        ruleMap.put(name, dataList);
                                        // 添加单一Host
                                        ConfigEntry.globalDataMap.put(host, ruleMap);
                                    }

                                    String[] splitHost = host.split("\\.");

                                    String anyHost = (splitHost.length > 2 && !MatchTool.matchIP(host)) ? StringHelper.replaceFirstOccurrence(host, splitHost[0], "*") : "";

                                    if (!ConfigEntry.globalDataMap.containsKey(anyHost) && anyHost.length() > 0) {
                                        // 添加通配符Host，实际数据从查询哪里将所有数据提取
                                        ConfigEntry.globalDataMap.put(anyHost, new HashMap<>());
                                    }

                                    if (!ConfigEntry.globalDataMap.containsKey("*")) {
                                        // 添加通配符全匹配，同上
                                        ConfigEntry.globalDataMap.put("*", new HashMap<>());
                                    }

                                    if (!ConfigEntry.globalDataMap.containsKey("**")) {
                                        // 添加通配符全匹配，同上
                                        ConfigEntry.globalDataMap.put("**", new HashMap<>());
                                    }
                                }
                            }
                        }
                    });
                    t.start();
                    try {
                        t.join();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                }
            });
            GlobalCachePool.addToCache(messageIndex, finalMap);
            return finalMap;
        }

    }
}