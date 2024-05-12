package hae.instances.http.utils;

import burp.api.montoya.MontoyaApi;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.AutomatonMatcher;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.RunAutomaton;
import hae.Config;
import hae.cache.CachePool;
import hae.utils.string.HashCalculator;
import hae.utils.string.StringProcessor;
import jregex.Matcher;
import jregex.Pattern;

import java.text.MessageFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RegularMatcher {
    private final MontoyaApi api;

    public RegularMatcher(MontoyaApi api) {
        this.api = api;

    }

    public Map<String, Map<String, Object>> match(String host, String type, String message, String header, String body) {
        // 先从缓存池里判断是否有已经匹配好的结果
        String messageIndex = HashCalculator.calculateHash(message.getBytes());
        Map<String, Map<String, Object>> map = CachePool.getFromCache(messageIndex);
        if (map != null) {
            return map;
        } else {
            // 最终返回的结果
            Map<String, Map<String, Object>> finalMap = new HashMap<>();
            Config.globalRules.keySet().parallelStream().forEach(i -> {
                for (Object[] objects : Config.globalRules.get(i)) {
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
                    if (loaded && (scope.contains(type) || scope.contains("any") || type.equals("any"))) {
                        switch (scope) {
                            case "any":
                            case "request":
                            case "response":
                                matchContent = message;
                                break;
                            case "any header":
                            case "request header":
                            case "response header":
                                matchContent = header;
                                break;
                            case "any body":
                            case "request body":
                            case "response body":
                                matchContent = body;
                                break;
                            case "request line":
                            case "response line":
                                matchContent = message.split("\\r?\\n", 2)[0];
                                break;
                            default:
                                break;
                        }

                        try {
                            result.addAll(matchByRegex(f_regex, s_regex, matchContent, format, engine, sensitive));
                        } catch (Exception e) {
                            api.logging().logToError(String.format("[x] Error Info:\nName: %s\nRegex: %s", name, f_regex));
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
                                if (Config.globalDataMap.containsKey(host)) {
                                    ConcurrentHashMap<String, List<String>> gRuleMap = new ConcurrentHashMap<>(Config.globalDataMap.get(host));
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
                                    Config.globalDataMap.remove(host);
                                    Config.globalDataMap.put(host, gRuleMap);
                                } else {
                                    Map<String, List<String>> ruleMap = new HashMap<>();
                                    ruleMap.put(name, dataList);
                                    // 添加单一Host
                                    Config.globalDataMap.put(host, ruleMap);
                                }

                                String[] splitHost = host.split("\\.");
                                String onlyHost = host.split(":")[0];

                                String anyHost = (splitHost.length > 2 && !onlyHost.matches("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")) ? StringProcessor.replaceFirstOccurrence(onlyHost, splitHost[0], "*") : "";

                                if (!Config.globalDataMap.containsKey(anyHost) && anyHost.length() > 0) {
                                    // 添加通配符Host，实际数据从查询哪里将所有数据提取
                                    Config.globalDataMap.put(anyHost, new HashMap<>());
                                }

                                if (!Config.globalDataMap.containsKey("*")) {
                                    // 添加通配符全匹配，同上
                                    Config.globalDataMap.put("*", new HashMap<>());
                                }
                            }
                        }
                    }
                }
            });
            CachePool.addToCache(messageIndex, finalMap);
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

    private List<String> getFormatString(Matcher matcher, String format) {
        List<Integer> indexList = parseIndexesFromString(format);
        List<String> stringList = new ArrayList<>();

        while (matcher.find()) {
            if (!matcher.group(1).isEmpty()) {
                Object[] params = indexList.stream().map(i -> {
                    if (!matcher.group(i + 1).isEmpty()) {
                        return matcher.group(i + 1);
                    }
                    return "";
                }).toArray();

                stringList.add(MessageFormat.format(reorderIndex(format), params));
            }
        }

        return stringList;
    }

    private List<String> getFormatString(AutomatonMatcher matcher, String content) {
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
        byte[] contentByte = api.utilities().byteUtils().convertFromString(content);
        byte[] sByte = api.utilities().byteUtils().convertFromString(s);
        int startIndex = api.utilities().byteUtils().indexOf(contentByte, sByte, false, 1, contentByte.length);
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
