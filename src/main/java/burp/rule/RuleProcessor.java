package burp.rule;

import burp.config.ConfigEntry;
import burp.config.ConfigLoader;
import burp.rule.model.Rule;
import burp.rule.model.RuleGroup;
import burp.rule.utils.YamlTool;
import java.io.IOException;
import java.nio.file.Files;
import java.util.stream.Collectors;
import org.yaml.snakeyaml.Yaml;
import java.io.File;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * @author EvilChen
 */

public class RuleProcessor {
    public void rulesFormatAndSave() {
        Yaml yaml = YamlTool.newStandardYaml();
        List<RuleGroup> ruleGroupList = new ArrayList<>();

        ConfigEntry.globalRules.forEach((k, v) -> {
            List<Rule> ruleList = Arrays.stream(v)
                    .map(objects -> new Rule(
                            (boolean) objects[0],
                            (String) objects[1],
                            (String) objects[2],
                            (String) objects[3],
                            (String) objects[4],
                            (String) objects[5],
                            (boolean) objects[6]))
                    .collect(Collectors.toList());
            ruleGroupList.add(new RuleGroup(k, ruleList));
        });

        List<Map<String, Object>> outputGroupsMap = ruleGroupList.stream()
                .map(RuleGroup::getFields)
                .collect(Collectors.toList());

        Map<String, Object> outputMap = new LinkedHashMap<>();
        outputMap.put("rules", outputGroupsMap);

        File f = new File(ConfigLoader.getRulesFilePath());
        try (Writer ws = new OutputStreamWriter(Files.newOutputStream(f.toPath()), StandardCharsets.UTF_8)) {
            yaml.dump(outputMap, ws);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public void changeRule(Vector data, int select, String type) {
        ConfigEntry.globalRules.get(type)[select] = data.toArray();
        this.rulesFormatAndSave();
    }

    public void addRule(Vector data, String type) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(ConfigEntry.globalRules.get(type)));
        x.add(data.toArray());
        ConfigEntry.globalRules.put(type,x.toArray(new Object[x.size()][]));
        this.rulesFormatAndSave();
    }
    public void removeRule(int select,String type) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(ConfigEntry.globalRules.get(type)));
        x.remove(select);
        ConfigEntry.globalRules.put(type,x.toArray(new Object[x.size()][]));
        this.rulesFormatAndSave();
    }

    public void renameRuleGroup(String oldName, String newName) {
        ConfigEntry.globalRules.put(newName, ConfigEntry.globalRules.remove(oldName));
        this.rulesFormatAndSave();
    }

    public void deleteRuleGroup(String Rules) {
        ConfigEntry.globalRules.remove(Rules);
        this.rulesFormatAndSave();
    }
    public String newRule() {
        int i = 0;
        String name = "New ";
        Object[][] data = new Object[][] {
                {
                    false, "New Name", "(New Regex)", "gray", "any", "nfa", false
                }
        };
        while (ConfigEntry.globalRules.containsKey(name + i)) {
            i++;
        }
        ConfigEntry.globalRules.put(name + i, data);
        this.rulesFormatAndSave();
        return name + i;
    }
}
