package hae.utils;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
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

    public ConfigLoader(MontoyaApi api) {
        this.api = api;
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Representer representer = new Representer(dop);
        this.yaml = new Yaml(representer, dop);

        String configPath = determineConfigPath();
        this.configFilePath = String.format("%s/%s", configPath, "Config.yml");
        this.rulesFilePath = String.format("%s/%s", configPath, "Rules.yml");

        // 构造函数，初始化配置
        File HaEConfigPathFile = new File(configPath);
        if (!(HaEConfigPathFile.exists() && HaEConfigPathFile.isDirectory())) {
            HaEConfigPathFile.mkdirs();
        }

        File configFilePath = new File(this.configFilePath);
        if (!(configFilePath.exists() && configFilePath.isFile())) {
            initConfig();
        }

        File rulesFilePath = new File(this.rulesFilePath);
        if (!(rulesFilePath.exists() && rulesFilePath.isFile())) {
            initRules();
        }

        Config.globalRules = getRules();
    }

    private static boolean isValidConfigPath(String configPath) {
        File configPathFile = new File(configPath);
        return configPathFile.exists() && configPathFile.isDirectory();
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
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ExcludeSuffix", getExcludeSuffix());
        r.put("BlockHost", getBlockHost());
        r.put("ExcludeStatus", getExcludeStatus());
        r.put("LimitSize", getLimitSize());
        r.put("HaEScope", getScope());
        try {
            Writer ws = new OutputStreamWriter(Files.newOutputStream(Paths.get(configFilePath)), StandardCharsets.UTF_8);
            yaml.dump(r, ws);
            ws.close();
        } catch (Exception ignored) {
        }
    }

    public String getRulesFilePath() {
        return rulesFilePath;
    }

    // 获取规则配置
    public Map<String, Object[][]> getRules() {
        Map<String, Object[][]> rules = new HashMap<>();

        try {
            InputStream inputStream = Files.newInputStream(Paths.get(getRulesFilePath()));
            DumperOptions dop = new DumperOptions();
            dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            Representer representer = new Representer(dop);
            Map<String, Object> rulesMap = new Yaml(representer, dop).load(inputStream);

            Object rulesObj = rulesMap.get("rules");
            if (rulesObj instanceof List) {
                List<Map<String, Object>> groupData = (List<Map<String, Object>>) rulesObj;
                for (Map<String, Object> groupFields : groupData) {
                    ArrayList<Object[]> data = new ArrayList<>();

                    Object ruleObj = groupFields.get("rule");
                    if (ruleObj instanceof List) {
                        List<Map<String, Object>> ruleData = (List<Map<String, Object>>) ruleObj;
                        for (Map<String, Object> ruleFields : ruleData) {
                            Object[] valuesArray = new Object[Config.ruleFields.length];
                            for (int i = 0; i < Config.ruleFields.length; i++) {
                                valuesArray[i] = ruleFields.get(Config.ruleFields[i].toLowerCase().replace("-", "_"));
                            }
                            data.add(valuesArray);
                        }
                    }

                    Object[][] dataArray = data.toArray(new Object[data.size()][]);
                    rules.put(groupFields.get("group").toString(), dataArray);
                }
            }

            return rules;
        } catch (Exception ignored) {
        }

        return rules;
    }

    public String getBlockHost() {
        return getValueFromConfig("BlockHost", Config.host);
    }

    public void setBlockHost(String blockHost) {
        setValueToConfig("BlockHost", blockHost);
    }

    public String getExcludeSuffix() {
        return getValueFromConfig("ExcludeSuffix", Config.suffix);
    }

    public void setExcludeSuffix(String excludeSuffix) {
        setValueToConfig("ExcludeSuffix", excludeSuffix);
    }

    public String getExcludeStatus() {
        return getValueFromConfig("ExcludeStatus", Config.status);
    }

    public void setExcludeStatus(String status) {
        setValueToConfig("ExcludeStatus", status);
    }

    public String getLimitSize() {
        return getValueFromConfig("LimitSize", Config.size);
    }

    public void setLimitSize(String size) {
        setValueToConfig("LimitSize", size);
    }

    public String getScope() {
        return getValueFromConfig("HaEScope", Config.scopeOptions);
    }

    public void setScope(String scope) {
        setValueToConfig("HaEScope", scope);
    }

    public boolean getMode() {
        return getValueFromConfig("HaEModeStatus", Config.modeStatus).equals("true");
    }

    public void setMode(String mode) {
        setValueToConfig("HaEModeStatus", mode);
    }

    private String getValueFromConfig(String name, String defaultValue) {
        File yamlSetting = new File(configFilePath);
        if (!yamlSetting.exists() || !yamlSetting.isFile()) {
            return defaultValue;
        }

        try (InputStream inorder = Files.newInputStream(Paths.get(configFilePath))) {
            Map<String, Object> r = new Yaml().load(inorder);

            if (r.containsKey(name)) {
                return r.get(name).toString();
            }
        } catch (Exception ignored) {
        }

        return defaultValue;
    }

    private void setValueToConfig(String name, String value) {
        Map<String, Object> currentConfig = loadCurrentConfig();
        currentConfig.put(name, value);

        try (Writer ws = new OutputStreamWriter(Files.newOutputStream(Paths.get(configFilePath)), StandardCharsets.UTF_8)) {
            yaml.dump(currentConfig, ws);
        } catch (Exception ignored) {
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
        } catch (Exception ignored) {
        }

        return false;
    }
}
