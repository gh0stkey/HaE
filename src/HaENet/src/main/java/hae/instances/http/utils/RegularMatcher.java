package hae.instances.http.utils;

import burp.api.montoya.MontoyaApi;
import dk.brics.automaton.Automaton;
import dk.brics.automaton.AutomatonMatcher;
import dk.brics.automaton.RegExp;
import dk.brics.automaton.RunAutomaton;
import hae.AppConstants;
import hae.cache.DataCache;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.string.HashCalculator;
import hae.utils.rule.model.RuleDefinition;

import java.text.MessageFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegularMatcher {
    private static final Map<String, Pattern> nfaPatternCache = new ConcurrentHashMap<>();
    private static final Map<String, RunAutomaton> dfaAutomatonCache = new ConcurrentHashMap<>();
    private static final Pattern formatIndexPattern = Pattern.compile("\\{(\\d+)}");
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final DataRepository dataRepository;
    private final RuleRepository ruleRepository;

    public RegularMatcher(MontoyaApi api, ConfigLoader configLoader, DataRepository dataRepository, RuleRepository ruleRepository) {
        this.api = api;
        this.configLoader = configLoader;
        this.dataRepository = dataRepository;
        this.ruleRepository = ruleRepository;
    }

    public Map<String, Map<String, Object>> performRegexMatching(String host, String url, String type, String message, String header, String body) {
        // 删除动态响应头再进行存储
        String originalMessage = message;
        String dynamicHeader = configLoader.getDynamicHeader();

        if (!dynamicHeader.isBlank()) {
            String modifiedHeader = header.replaceAll(String.format("(%s):.*?\r\n", configLoader.getDynamicHeader()), "");
            message = message.replace(header, modifiedHeader);
        }

        String messageIndex = HashCalculator.calculateHash((host + "|" + message).getBytes());

        // 从数据缓存中读取
        Map<String, Map<String, Object>> dataCacheMap = DataCache.get(messageIndex);

        // 存在则返回
        if (dataCacheMap != null) {
            return dataCacheMap;
        }

        // 最终返回的结果
        String firstLine = originalMessage.split("\\r?\\n", 2)[0];
        Map<String, Map<String, Object>> finalMap = applyMatchingRules(host, url, type, originalMessage, firstLine, header, body);

        // 数据缓存写入，有可能是空值，当作匹配过的索引不再匹配
        DataCache.put(messageIndex, finalMap);

        return finalMap;
    }

    private Map<String, Map<String, Object>> applyMatchingRules(String host, String url, String type, String message, String firstLine, String header, String body) {
        Map<String, Map<String, Object>> finalMap = new ConcurrentHashMap<>();

        ruleRepository.getAllGroupNames().parallelStream().forEach(i -> {
            for (RuleDefinition rule : ruleRepository.getRulesByGroup(i)) {
                String matchContent = "";
                // 遍历获取规则
                List<String> result;
                Map<String, Object> tmpMap = new HashMap<>();

                boolean loaded = rule.isLoaded();
                String name = rule.getName();
                String firstRegex = rule.getFirstRegex();
                String secondRegex = rule.getSecondRegex();
                String format = rule.getFormat();
                String color = rule.getColor();
                String scope = rule.getScope();
                String engine = rule.getEngine();
                boolean sensitive = rule.isSensitive();

                // 判断规则是否开启与作用域
                if (loaded && (scope.contains(type) || scope.contains("any") || type.equals("any"))) {
                    // 在此处检查内容是否缓存，缓存则返回为空
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
                            matchContent = firstLine;
                            break;
                        default:
                            break;
                    }

                    // 匹配内容为空则跳过当前规则，继续下一条规则
                    if (matchContent.isBlank()) {
                        continue;
                    }

                    try {
                        result = new ArrayList<>(executeRegexEngine(firstRegex, secondRegex, matchContent, format, engine, sensitive));
                    } catch (Exception e) {
                        api.logging().logToError(String.format("[x] Error Info:\nName: %s\nRegex: %s", name, firstRegex));
                        api.logging().logToError(e.getMessage());
                        continue;
                    }

                    // 去除重复内容
                    Set<String> tmpSet = new LinkedHashSet<>(result);
                    result.clear();
                    result.addAll(tmpSet);

                    if (!result.isEmpty()) {
                        tmpMap.put("color", color);
                        String dataStr = String.join(AppConstants.boundary, result);
                        tmpMap.put("data", dataStr);

                        String nameAndSize = String.format("%s (%s)", name, result.size());
                        finalMap.put(nameAndSize, tmpMap);

                        // 提取匹配内容的上下文（前后各50个字符）
                        for (String match : result) {
                            ValidatorService.putContext(name, match, matchContent);
                            ValidatorService.putUrl(name, match, url);
                        }

                        dataRepository.mergeData(host, name, result, true);
                    }
                }
            }
        });

        return finalMap;
    }

    private List<String> executeRegexEngine(String firstRegex, String secondRegex, String content, String format, String engine, boolean sensitive) {
        List<String> retList = new ArrayList<>();
        if ("nfa".equals(engine)) {
            Matcher matcher = createPatternMatcher(firstRegex, content, sensitive);
            retList.addAll(extractRegexMatchResults(secondRegex, format, sensitive, matcher));
        } else {
            // DFA不支持格式化输出，因此不关注format
            String newContent = content;
            String newFirstRegex = firstRegex;
            if (!sensitive) {
                newContent = content.toLowerCase();
                newFirstRegex = firstRegex.toLowerCase();
            }
            AutomatonMatcher autoMatcher = createAutomatonMatcher(newFirstRegex, newContent);
            retList.addAll(extractRegexMatchResults(secondRegex, autoMatcher, content));
        }
        return retList;
    }

    private List<String> extractRegexMatchResults(String secondRegex, String format, boolean sensitive, Matcher matcher) {
        List<String> matches = new ArrayList<>();
        if (secondRegex.isEmpty()) {
            matches.addAll(formatMatchResults(matcher, format));
        } else {
            while (matcher.find()) {
                String matchContent = matcher.group(1);
                if (!matchContent.isEmpty()) {
                    Matcher secondMatcher = createPatternMatcher(secondRegex, matchContent, sensitive);
                    matches.addAll(formatMatchResults(secondMatcher, format));
                }
            }
        }
        return matches;
    }

    private List<String> extractRegexMatchResults(String secondRegex, AutomatonMatcher autoMatcher, String content) {
        List<String> matches = new ArrayList<>();
        if (secondRegex.isEmpty()) {
            matches.addAll(formatMatchResults(autoMatcher, content));
        } else {
            while (autoMatcher.find()) {
                String s = autoMatcher.group();
                if (!s.isEmpty()) {
                    autoMatcher = createAutomatonMatcher(secondRegex, extractMatchedContent(content, s));
                    matches.addAll(formatMatchResults(autoMatcher, content));
                }
            }
        }
        return matches;
    }

    private List<String> formatMatchResults(Matcher matcher, String format) {
        List<String> stringList = new ArrayList<>();

        // 当format为{0}时，直接返回第一个捕获组，避免格式化开销
        if ("{0}".equals(format)) {
            while (matcher.find()) {
                if (matcher.groupCount() > 0 && !matcher.group(1).isEmpty()) {
                    stringList.add(matcher.group(1));
                }
            }
            return stringList;
        }

        // 需要复杂格式化的情况
        List<Integer> indexList = parseIndexesFromString(format);
        while (matcher.find()) {
            if (!matcher.group(1).isEmpty()) {
                Object[] params = indexList.stream().map(i -> {
                    if (!matcher.group(i + 1).isEmpty()) {
                        return matcher.group(i + 1);
                    }
                    return "";
                }).toArray();

                stringList.add(MessageFormat.format(normalizeFormatIndexes(format), params));
            }
        }

        return stringList;
    }

    private List<String> formatMatchResults(AutomatonMatcher matcher, String content) {
        List<String> stringList = new ArrayList<>();

        while (matcher.find()) {
            String s = matcher.group(0);
            if (!s.isEmpty()) {
                stringList.add(extractMatchedContent(content, s));
            }
        }

        return stringList;
    }

    private Matcher createPatternMatcher(String regex, String content, boolean sensitive) {
        String cacheKey = regex + "|" + sensitive;
        Pattern pattern = nfaPatternCache.computeIfAbsent(cacheKey, k -> {
            int flags = sensitive ? 0 : Pattern.CASE_INSENSITIVE;
            return Pattern.compile(regex, flags);
        });

        return pattern.matcher(content);
    }

    private AutomatonMatcher createAutomatonMatcher(String regex, String content) {
        RunAutomaton runAuto = dfaAutomatonCache.computeIfAbsent(regex, k -> {
            RegExp regexp = new RegExp(regex);
            Automaton auto = regexp.toAutomaton();
            return new RunAutomaton(auto, true);
        });

        return runAuto.newMatcher(content);
    }

    private LinkedList<Integer> parseIndexesFromString(String input) {
        LinkedList<Integer> indexes = new LinkedList<>();
        Matcher matcher = formatIndexPattern.matcher(input);

        while (matcher.find()) {
            String index = matcher.group(1);
            if (!index.isEmpty()) {
                indexes.add(Integer.valueOf(index));
            }
        }

        return indexes;
    }

    private String extractMatchedContent(String content, String s) {
        byte[] contentByte = api.utilities().byteUtils().convertFromString(content);
        byte[] sByte = api.utilities().byteUtils().convertFromString(s);
        int startIndex = api.utilities().byteUtils().indexOf(contentByte, sByte, false, 1, contentByte.length);
        int endIndex = startIndex + s.length();

        return content.substring(startIndex, endIndex);
    }

    private String normalizeFormatIndexes(String format) {
        Matcher matcher = formatIndexPattern.matcher(format);
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
