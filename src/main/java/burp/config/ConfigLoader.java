package burp.config;

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
    private static final String HaEConfigPath = String.format("%s/.config/HaE", System.getProperty("user.home"));
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
            initRules();
        }
        ConfigEntry.globalRules = ConfigLoader.getRules();
    }

    public void initConfig() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("rulesPath", RulesFilePath);
        r.put("excludeSuffix", getExcludeSuffix());
        try {
            Writer ws = new OutputStreamWriter(Files.newOutputStream(Paths.get(ConfigFilePath)), StandardCharsets.UTF_8);
            yaml.dump(r, ws);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public void initRules() {
        RuleTool rt = new RuleTool(RulesFilePath);
        rt.getRulesFromSite();
    }

    public static String getRulesFilePath() {
        try {
            Map<String, Object> r = YamlTool.loadYaml(ConfigFilePath);
            return r.get("rulesPath").toString();
        } catch (Exception e) {
            e.printStackTrace();
            return RulesFilePath;
        }
    }

    public String getExcludeSuffix(){
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
        String[] fieldKeys = {"loaded", "name", "regex", "color", "scope", "engine", "sensitive"};

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

    public void setExcludeSuffix(String excludeSuffix){
        Map<String,Object> r = new LinkedHashMap<>();
        r.put("rulesPath", getRulesFilePath());
        r.put("excludeSuffix", excludeSuffix);
        try{
            Writer ws = new OutputStreamWriter(Files.newOutputStream(Paths.get(RulesFilePath)), StandardCharsets.UTF_8);
            yaml.dump(r, ws);
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }

}