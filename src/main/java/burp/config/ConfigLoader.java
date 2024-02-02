package burp.config;

import burp.BurpExtender;
import burp.rule.utils.RuleTool;
import burp.rule.utils.YamlTool;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import org.yaml.snakeyaml.Yaml;

/**
 * @author EvilChen
 */

public class ConfigLoader {
    private static final Yaml yaml = YamlTool.newStandardYaml();
    private static final String HaEConfigPath = determineConfigPath();
    private static final String RulesFilePath = String.format("%s/%s", HaEConfigPath, "Rules.yml");
    private static final String ConfigFilePath =  String.format("%s/%s", HaEConfigPath, "Config.yml");

    public ConfigLoader() {
        // 构造函数，初始化配置
        File HaEConfigPathFile = new File(HaEConfigPath);
        if (!(HaEConfigPathFile.exists() && HaEConfigPathFile.isDirectory())) {
            HaEConfigPathFile.mkdirs();
        }

        File configFilePath = new File(ConfigFilePath);
        if (!(configFilePath.exists() && configFilePath.isFile())) {
            initConfig();
        }

        File rulesFilePath = new File(RulesFilePath);
        if (!(rulesFilePath.exists() && rulesFilePath.isFile())) {
            initRules();
        }

        ConfigEntry.globalRules = getRules();
    }

    private static String determineConfigPath() {
        // 优先级1：用户根目录
        String userConfigPath = String.format("%s/.config/HaE", System.getProperty("user.home"));
        if (isValidConfigPath(userConfigPath)) {
            return userConfigPath;
        }

        // 优先级2：Jar包所在目录
        String jarPath = BurpExtender.callbacks.getExtensionFilename();
        String jarDirectory = new File(jarPath).getParent();
        String jarConfigPath = String.format("%s/.config/HaE", jarDirectory);
        if (isValidConfigPath(jarConfigPath)) {
            return jarConfigPath;
        }
        
        return userConfigPath;
    }

    private static boolean isValidConfigPath(String configPath) {
        File configPathFile = new File(configPath);
        return configPathFile.exists() && configPathFile.isDirectory();
    }

    public static void initConfig() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("excludeSuffix", getExcludeSuffix());
        try {
            Writer ws = new OutputStreamWriter(Files.newOutputStream(Paths.get(ConfigFilePath)), StandardCharsets.UTF_8);
            yaml.dump(r, ws);
            ws.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void initRules() {
        RuleTool rt = new RuleTool(RulesFilePath);
        rt.getRulesFromSite();
    }

    public static String getRulesFilePath() {
        return RulesFilePath;
    }

    public static String getExcludeSuffix(){
        String excludeSuffix = "";
        File yamlSetting = new File(ConfigFilePath);
        
        if (yamlSetting.exists() && yamlSetting.isFile()) {
            try {
                InputStream inorder = Files.newInputStream(Paths.get(ConfigFilePath));
                Map<String,Object> r = yaml.load(inorder);
                excludeSuffix = r.get("excludeSuffix").toString();
            } catch (Exception e) {
                // e.printStackTrace();
                excludeSuffix = ConfigEntry.excludeSuffix;
            }
        } else {
            excludeSuffix = ConfigEntry.excludeSuffix;
        }
        
        return excludeSuffix;
    }

    // 获取规则配置
    public static Map<String, Object[][]> getRules() {
        Map<String, Object> rulesMap = YamlTool.loadYaml(getRulesFilePath());
        Map<String, Object[][]> resRule = new HashMap<>();
        String[] fieldKeys = {"loaded", "name", "f_regex", "s_regex", "format", "color", "scope", "engine", "sensitive"};

        Object rulesObj = rulesMap.get("rules");
        if (rulesObj instanceof List) {
            List<Map<String, Object>> groupData = (List<Map<String, Object>>) rulesObj;
            for (Map<String, Object> groupFields : groupData) {
                ArrayList<Object[]> data = new ArrayList<>();

                Object ruleObj = groupFields.get("rule");
                if (ruleObj instanceof List) {
                    List<Map<String, Object>> ruleData = (List<Map<String, Object>>) ruleObj;
                    for (Map<String, Object> ruleFields : ruleData) {
                        Object[] valuesArray = new Object[fieldKeys.length];
                        for (int i = 0; i < fieldKeys.length; i++) {
                            valuesArray[i] = ruleFields.get(fieldKeys[i]);
                        }
                        data.add(valuesArray);
                    }
                }

                Object[][] dataArray = data.toArray(new Object[data.size()][]);
                resRule.put(groupFields.get("group").toString(), dataArray);
            }
        }
        return resRule;
    }

    public static void setExcludeSuffix(String excludeSuffix){
        Map<String,Object> r = new LinkedHashMap<>();
        r.put("excludeSuffix", excludeSuffix);
        try{
            Writer ws = new OutputStreamWriter(Files.newOutputStream(Paths.get(ConfigFilePath)), StandardCharsets.UTF_8);
            yaml.dump(r, ws);
            ws.close();
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }
}
