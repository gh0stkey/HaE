package hae.utils.rule;

import burp.api.montoya.MontoyaApi;
import hae.AppConstants;
import hae.cache.DataCache;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;
import hae.utils.rule.model.Group;
import hae.utils.rule.model.RuleDefinition;
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

        ruleRepository.getAll().forEach((k, v) ->
                ruleGroupList.add(new Group(k, v))
        );

        List<Map<String, Object>> outputGroupsMap = ruleGroupList.stream()
                .map(Group::getFields)
                .collect(Collectors.toList());

        Map<String, Object> outputMap = new LinkedHashMap<>();
        outputMap.put("rules", outputGroupsMap);

        File rulesFile = new File(configLoader.getRulesFilePath());
        try (Writer writer = new OutputStreamWriter(Files.newOutputStream(rulesFile.toPath()), StandardCharsets.UTF_8)) {
            yaml.dump(outputMap, writer);
        } catch (Exception e) {
            api.logging().logToError("Failed to save rules file: " + e.getMessage());
        }
    }

    public void changeRule(RuleDefinition rule, int select, String type) {
        ruleRepository.updateRule(type, select, rule);
        this.rulesFormatAndSave();
    }

    public void addRule(RuleDefinition rule, String type) {
        ruleRepository.addRule(type, rule);
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

    public void deleteRuleGroup(String groupName) {
        ruleRepository.removeGroup(groupName);
        this.rulesFormatAndSave();
    }

    public String newRule() {
        int i = 0;
        String name = "New ";

        while (ruleRepository.containsGroup(name + i)) {
            i++;
        }

        ruleRepository.putGroup(name + i, new ArrayList<>(AppConstants.ruleTemplate));
        this.rulesFormatAndSave();
        return name + i;
    }
}
