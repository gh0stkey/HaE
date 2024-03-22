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
import java.text.MessageFormat;
import java.util.*;

import java.util.concurrent.ConcurrentHashMap;
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
            ConfigEntry.globalRules.keySet().parallelStream().forEach(i -> {
                for (Object[] objects : ConfigEntry.globalRules.get(i)) {
                    // 多线程执行，一定程度上减少阻塞现象
                    String matchContent = "";
                    // 遍历获取规则
                    List<String> result = new ArrayList<>();
                    Map<String, Object> tmpMap = new HashMap<>();

                    boolean loaded = (Boolean) objects[0];
                    String name = objects[1].toString();
                    String f_regex = objects[2].toString();
                    String s_regex = objects[3].toString();
                    String format = objects[4].toString();
                    String color = objects[5].toString();
                    String scope = objects[6].toString();
                    String engine = objects[7].toString();
                    boolean sensitive = (Boolean) objects[8];

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

                        try {
                            result.addAll(matchByRegex(f_regex, s_regex, matchContent, format, engine, sensitive));
                        } catch (Exception e) {
                            BurpExtender.stdout.println(String.format("[x] Error Info:\nName: %s\nRegex: %s", name, f_regex));
                            e.printStackTrace();
                            continue;
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
                            if (!Objects.equals(host, "") && host != null) {
                                List<String> dataList = Arrays.asList(dataStr.split("\n"));
                                if (ConfigEntry.globalDataMap.containsKey(host)) {
                                    ConcurrentHashMap<String, List<String>> gRuleMap = new ConcurrentHashMap<>(ConfigEntry.globalDataMap.get(host));
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
                }
            });
            GlobalCachePool.addToCache(messageIndex, finalMap);
            return finalMap;
        }
    }

    private List<String> matchByRegex(String f_regex, String s_regex, String content, String format, String engine, boolean sensitive) {
        List<String> retList = new ArrayList<>();
        if ("nfa".equals(engine)) {
            Matcher matcher = createPatternMatcher(f_regex, content, sensitive);
            retList.addAll(extractMatches(s_regex, format, sensitive, matcher));
        } else {
            // DFA不支持格式化输出，因此不关注format
            String newContent = content;
            String newFirstRegex = f_regex;
            if (!sensitive) {
                newContent = content.toLowerCase();
                newFirstRegex = f_regex.toLowerCase();
            }
            AutomatonMatcher autoMatcher = createAutomatonMatcher(newFirstRegex, newContent);
            retList.addAll(extractMatches(s_regex, autoMatcher, content));
        }
        return retList;
    }

    private List<String> extractMatches(String s_regex, String format, boolean sensitive, Matcher matcher) {
        List<String> matches = new ArrayList<>();
        if (s_regex.isEmpty()) {
            matches.addAll(getFormatString(matcher, format));
        } else {
            while (matcher.find()) {
                String matchContent = matcher.group(1);
                if (!matchContent.isEmpty()) {
                    matcher = createPatternMatcher(s_regex, matchContent, sensitive);
                    matches.addAll(getFormatString(matcher, format));
                }
            }
        }
        return matches;
    }

    private List<String> extractMatches(String s_regex, AutomatonMatcher autoMatcher, String content) {
        List<String> matches = new ArrayList<>();
        if (s_regex.isEmpty()) {
            matches.addAll(getFormatString(autoMatcher, content));
        } else {
            while (autoMatcher.find()) {
                String s = autoMatcher.group();
                if (!s.isEmpty()) {
                    autoMatcher = createAutomatonMatcher(s_regex, getSubString(content, s));
                    matches.addAll(getFormatString(autoMatcher, content));
                }
            }
        }
        return matches;
    }

    public List<String> getFormatString(Matcher matcher, String format) {
        List<Integer> indexList = parseIndexesFromString(format);
        List<String> stringList = new ArrayList<>();

        while (matcher.find()) {
            if (!matcher.group(1).isEmpty()) {
                Object[] params = indexList.stream().map(i -> {
                    if (!matcher.group(i+1).isEmpty()) {
                        return matcher.group(i+1);
                    }
                    return "";
                }).toArray();

                stringList.add(MessageFormat.format(reorderIndex(format), params));
            }
        }

        return stringList;
    }

    public List<String> getFormatString(AutomatonMatcher matcher, String content) {
        List<String> stringList = new ArrayList<>();

        while (matcher.find()) {
            String s = matcher.group(0);
            if (!s.isEmpty()) {
                stringList.add(getSubString(content, s));
            }
        }

        return stringList;
    }

    private Matcher createPatternMatcher(String regex, String content, boolean sensitive) {
        Pattern pattern = (sensitive) ? new Pattern(regex) : new Pattern(regex, Pattern.IGNORE_CASE);
        return pattern.matcher(content);
    }

    private AutomatonMatcher createAutomatonMatcher(String regex, String content) {
        RegExp regexp = new RegExp(regex);
        Automaton auto = regexp.toAutomaton();
        RunAutomaton runAuto = new RunAutomaton(auto, true);
        return runAuto.newMatcher(content);
    }

    private LinkedList<Integer> parseIndexesFromString(String input) {
        LinkedList<Integer> indexes = new LinkedList<>();
        Pattern pattern = new Pattern("\\{(\\d+)}");
        Matcher matcher = pattern.matcher(input);

        while (matcher.find()) {
            String index = matcher.group(1);
            if (!index.isEmpty()) {
                indexes.add(Integer.valueOf(index));
            }
        }

        return indexes;
    }

    private String getSubString(String content, String s) {
        byte[] contentByte = BurpExtender.helpers.stringToBytes(content);
        byte[] sByte = BurpExtender.helpers.stringToBytes(s);
        int startIndex = BurpExtender.helpers.indexOf(contentByte, sByte, false, 1, contentByte.length);
        int endIndex = startIndex + s.length();
        return content.substring(startIndex, endIndex);
    }

    private String reorderIndex(String format) {
        Pattern pattern = new Pattern("\\{(\\d+)}");
        Matcher matcher = pattern.matcher(format);
        int count = 0;
        while (matcher.find()) {
            String newStr = String.format("{%s}", count);
            String matchStr = matcher.group(0);
            format = format.replace(matchStr, newStr);
            count++;
        }
        return format;
    }
}

