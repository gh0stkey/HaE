package hae.utils.rule;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import hae.utils.rule.model.Group;
import hae.utils.rule.model.Info;
import hae.utils.config.ConfigLoader;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

public class RuleProcessor {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;

    public RuleProcessor(MontoyaApi api, ConfigLoader configLoader) {
        this.api = api;
        this.configLoader = configLoader;
    }

    public void rulesFormatAndSave() {
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Representer representer = new Representer(dop);
        Yaml yaml = new Yaml(representer, dop);

        List<Group> ruleGroupList = new ArrayList<>();

        Config.globalRules.forEach((k, v) -> {
            List<Info> ruleList = Arrays.stream(v)
                    .map(objects -> new Info(
                            (boolean) objects[0],
                            (String) objects[1],
                            (String) objects[2],
                            (String) objects[3],
                            (String) objects[4],
                            (String) objects[5],
                            (String) objects[6],
                            (String) objects[7],
                            (boolean) objects[8]))
                    .collect(Collectors.toList());
            ruleGroupList.add(new Group(k, ruleList));
        });

        List<Map<String, Object>> outputGroupsMap = ruleGroupList.stream()
                .map(Group::getFields)
                .collect(Collectors.toList());

        Map<String, Object> outputMap = new LinkedHashMap<>();
        outputMap.put("rules", outputGroupsMap);

        File f = new File(configLoader.getRulesFilePath());
        try (Writer ws = new OutputStreamWriter(Files.newOutputStream(f.toPath()), StandardCharsets.UTF_8)) {
            yaml.dump(outputMap, ws);
        } catch (Exception ignored) {
        }
    }

    public void changeRule(Vector data, int select, String type) {
        Config.globalRules.get(type)[select] = data.toArray();
        this.rulesFormatAndSave();
    }

    public void addRule(Vector data, String type) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(Config.globalRules.get(type)));
        x.add(data.toArray());
        Config.globalRules.put(type,x.toArray(new Object[x.size()][]));
        this.rulesFormatAndSave();
    }
    public void removeRule(int select,String type) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(Config.globalRules.get(type)));
        x.remove(select);
        Config.globalRules.put(type,x.toArray(new Object[x.size()][]));
        this.rulesFormatAndSave();
    }

    public void renameRuleGroup(String oldName, String newName) {
        Config.globalRules.put(newName, Config.globalRules.remove(oldName));
        this.rulesFormatAndSave();
    }

    public void deleteRuleGroup(String Rules) {
        Config.globalRules.remove(Rules);
        this.rulesFormatAndSave();
    }

    public String newRule() {
        int i = 0;
        String name = "New ";

        while (Config.globalRules.containsKey(name + i)) {
            i++;
        }

        Config.globalRules.put(name + i, Config.ruleTemplate);
        this.rulesFormatAndSave();
        return name + i;
    }
}


