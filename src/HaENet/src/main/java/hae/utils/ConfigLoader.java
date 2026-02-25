package hae.utils;

import burp.api.montoya.MontoyaApi;
import hae.AppConstants;
import hae.utils.rule.model.RuleDefinition;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.representer.Representer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class ConfigLoader {
    private final MontoyaApi api;
    private final Yaml yaml;
    private final String configFilePath;
    private final String rulesFilePath;
    private volatile Map<String, Object> configCache;

    public ConfigLoader(MontoyaApi api) {
        this.api = api;
        this.yaml = createSecureYaml();

        String configPath = determineConfigPath();
        this.configFilePath = String.format("%s/%s", configPath, "Config.yml");
        this.rulesFilePath = String.format("%s/%s", configPath, "Rules.yml");

        // 构造函数，初始化配置
        File configDir = new File(configPath);
        if (!(configDir.exists() && configDir.isDirectory())) {
            configDir.mkdirs();
        }

        File configFilePath = new File(this.configFilePath);
        if (!(configFilePath.exists() && configFilePath.isFile())) {
            initConfig();
        }

        File rulesFilePath = new File(this.rulesFilePath);
        if (!(rulesFilePath.exists() && rulesFilePath.isFile())) {
            initRules();
        }

    }

    private static boolean isValidConfigPath(String configPath) {
        File configPathFile = new File(configPath);
        return configPathFile.exists() && configPathFile.isDirectory();
    }

    private Yaml createSecureYaml() {
        // 配置 LoaderOptions 进行安全限制
        LoaderOptions loaderOptions = new LoaderOptions();
        // 禁用注释处理
        loaderOptions.setProcessComments(false);
        // 禁止递归键
        loaderOptions.setAllowRecursiveKeys(false);

        // 配置 DumperOptions 控制输出格式
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

        // 创建 Representer
        Representer representer = new Representer(dop);

        // 使用 SafeConstructor创建安全的 YAML 实例
        return new Yaml(new SafeConstructor(loaderOptions), representer, dop);
    }

    private String determineConfigPath() {
        // 优先级1：用户根目录
        String userConfigPath = String.format("%s/.config/HaE", System.getProperty("user.home"));
        if (isValidConfigPath(userConfigPath)) {
            return userConfigPath;
        }

        // 优先级2：Jar包所在目录
        String jarPath = api.extension().filename();
        String jarDirectory = new File(jarPath).getParent();
        String jarConfigPath = String.format("%s/.config/HaE", jarDirectory);
        if (isValidConfigPath(jarConfigPath)) {
            return jarConfigPath;
        }

        return userConfigPath;
    }

    public void initConfig() {
        Map<String, Object> configMap = new LinkedHashMap<>();
        configMap.put("ExcludeSuffix", getExcludeSuffix());
        configMap.put("BlockHost", getBlockHost());
        configMap.put("ExcludeStatus", getExcludeStatus());
        configMap.put("LimitSize", getLimitSize());
        configMap.put("HaEScope", getScope());
        configMap.put("DynamicHeader", getDynamicHeader());

        try {
            Writer writer = new OutputStreamWriter(Files.newOutputStream(Paths.get(configFilePath)), StandardCharsets.UTF_8);
            yaml.dump(configMap, writer);
            writer.close();
        } catch (Exception e) {
            api.logging().logToError("Failed to init config: " + e.getMessage());
        }
    }

    public String getRulesFilePath() {
        return rulesFilePath;
    }

    // 获取规则配置
    public Map<String, List<RuleDefinition>> getRules() {
        Map<String, List<RuleDefinition>> rules = new HashMap<>();

        try {
            InputStream inputStream = Files.newInputStream(Paths.get(getRulesFilePath()));
            Map<String, Object> rulesMap = yaml.load(inputStream);

            Object rulesObj = rulesMap.get("rules");
            if (rulesObj instanceof List) {
                List<Map<String, Object>> groupData = (List<Map<String, Object>>) rulesObj;
                for (Map<String, Object> groupFields : groupData) {
                    List<RuleDefinition> data = new ArrayList<>();

                    Object ruleObj = groupFields.get("rule");
                    if (ruleObj instanceof List) {
                        List<Map<String, Object>> ruleData = (List<Map<String, Object>>) ruleObj;
                        for (Map<String, Object> ruleFields : ruleData) {
                            data.add(RuleDefinition.fromYamlMap(ruleFields));
                        }
                    }

                    rules.put(groupFields.get("group").toString(), data);
                }
            }

            return rules;
        } catch (Exception e) {
            api.logging().logToError("Failed to load rules: " + e.getMessage());
        }

        return rules;
    }

    public String getBlockHost() {
        return getValueFromConfig("BlockHost", AppConstants.host);
    }

    public void setBlockHost(String blockHost) {
        setValueToConfig("BlockHost", blockHost);
    }

    public String getExcludeSuffix() {
        return getValueFromConfig("ExcludeSuffix", AppConstants.suffix);
    }

    public void setExcludeSuffix(String excludeSuffix) {
        setValueToConfig("ExcludeSuffix", excludeSuffix);
    }

    public String getExcludeStatus() {
        return getValueFromConfig("ExcludeStatus", AppConstants.status);
    }

    public void setExcludeStatus(String status) {
        setValueToConfig("ExcludeStatus", status);
    }

    public String getDynamicHeader() {
        return getValueFromConfig("DynamicHeader", AppConstants.header);
    }

    public void setDynamicHeader(String header) {
        setValueToConfig("DynamicHeader", header);
    }

    public String getLimitSize() {
        return getValueFromConfig("LimitSize", AppConstants.size);
    }

    public void setLimitSize(String size) {
        setValueToConfig("LimitSize", size);
    }

    public String getScope() {
        return getValueFromConfig("HaEScope", AppConstants.scopeOptions);
    }

    public void setScope(String scope) {
        setValueToConfig("HaEScope", scope);
    }

    public boolean getMode() {
        return getValueFromConfig("HaEModeStatus", AppConstants.modeStatus).equals("true");
    }

    public void setMode(String mode) {
        setValueToConfig("HaEModeStatus", mode);
    }

    private String getValueFromConfig(String name, String defaultValue) {
        Map<String, Object> configData = getConfigData();
        if (configData != null && configData.containsKey(name)) {
            return configData.get(name).toString();
        }
        return defaultValue;
    }

    private Map<String, Object> getConfigData() {
        Map<String, Object> cached = configCache;
        if (cached != null) {
            return cached;
        }

        File yamlSetting = new File(configFilePath);
        if (!yamlSetting.exists() || !yamlSetting.isFile()) {
            return null;
        }

        try (InputStream inputStream = Files.newInputStream(Paths.get(configFilePath))) {
            cached = yaml.load(inputStream);
            configCache = cached;
            return cached;
        } catch (Exception e) {
            api.logging().logToError("Failed to load config: " + e.getMessage());
        }

        return null;
    }

    private void setValueToConfig(String name, String value) {
        Map<String, Object> currentConfig = loadCurrentConfig();
        currentConfig.put(name, value);

        try (Writer writer = new OutputStreamWriter(Files.newOutputStream(Paths.get(configFilePath)), StandardCharsets.UTF_8)) {
            yaml.dump(currentConfig, writer);
            configCache = null; // 写入后失效缓存
        } catch (Exception e) {
            api.logging().logToError("Failed to save config: " + e.getMessage());
        }
    }

    private Map<String, Object> loadCurrentConfig() {
        Path path = Paths.get(configFilePath);
        if (!Files.exists(path)) {
            return new LinkedHashMap<>(); // 返回空的Map，表示没有当前配置
        }

        try (InputStream in = Files.newInputStream(path)) {
            return yaml.load(in);
        } catch (Exception e) {
            return new LinkedHashMap<>(); // 读取失败时也返回空的Map
        }
    }

    public boolean initRules() {
        boolean ret = copyRulesToFile(this.rulesFilePath);
        if (!ret) {
            api.extension().unload();
        }
        return ret;
    }

    private boolean copyRulesToFile(String targetFilePath) {
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("rules/Rules.yml");
        File targetFile = new File(targetFilePath);

        try (inputStream; OutputStream outputStream = new FileOutputStream(targetFile)) {
            if (inputStream != null) {
                byte[] buffer = new byte[1024];
                int length;

                while ((length = inputStream.read(buffer)) > 0) {
                    outputStream.write(buffer, 0, length);
                }

                return true;
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to copy rules file: " + e.getMessage());
        }

        return false;
    }
}
