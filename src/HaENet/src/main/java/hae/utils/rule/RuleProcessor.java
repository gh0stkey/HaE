package hae.utils.rule;

import burp.api.montoya.MontoyaApi;
import hae.cache.DataCache;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;
import hae.utils.rule.model.Group;
import hae.utils.rule.model.Info;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
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
    private final RuleRepository ruleRepository;

    public RuleProcessor(MontoyaApi api, ConfigLoader configLoader, RuleRepository ruleRepository) {
        this.api = api;
        this.configLoader = configLoader;
        this.ruleRepository = ruleRepository;
    }

    public void rulesFormatAndSave() {
        DataCache.clear();

        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Representer representer = new Representer(dop);
        Yaml yaml = new Yaml(representer, dop);

        List<Group> ruleGroupList = new ArrayList<>();

        ruleRepository.getAll().forEach((k, v) -> {
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
        ruleRepository.updateRule(type, select, data.toArray());
        this.rulesFormatAndSave();
    }

    public void addRule(Vector data, String type) {
        ruleRepository.addRule(type, data.toArray());
        this.rulesFormatAndSave();
    }

    public void removeRule(int select, String type) {
        ruleRepository.removeRule(type, select);
        this.rulesFormatAndSave();
    }

    public void renameRuleGroup(String oldName, String newName) {
        ruleRepository.renameGroup(oldName, newName);
        this.rulesFormatAndSave();
    }

    public void deleteRuleGroup(String Rules) {
        ruleRepository.removeGroup(Rules);
        this.rulesFormatAndSave();
    }

    public String newRule() {
        int i = 0;
        String name = "New ";

        while (ruleRepository.containsGroup(name + i)) {
            i++;
        }

        ruleRepository.putGroup(name + i, hae.Config.ruleTemplate);
        this.rulesFormatAndSave();
        return name + i;
    }
}
