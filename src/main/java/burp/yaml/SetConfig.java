package burp.yaml;

import burp.Config;
import burp.yaml.template.Rule;
import burp.yaml.template.Rules;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class SetConfig {

    public void format() {
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Representer representer = new Representer();
        representer.addClassTag(RulesConfig.class, Tag.MAP);
        Yaml yaml = new Yaml(new Constructor(), representer, dop);
        RulesConfig con = new RulesConfig();
        List<Rules> rls = new ArrayList<>();

        Config.ruleConfig.keySet().forEach(i->
        {
            Rules rlsTmp = new Rules();
            rlsTmp.setType(i);
            List<Rule> rl = new ArrayList<>();
            for (Object[] objects : Config.ruleConfig.get(i)) {
                Rule rlTmp = new Rule();
                rlTmp.setName((String) objects[1]);
                rlTmp.setLoaded((Boolean) objects[0]);
                rlTmp.setRegex((String) objects[2]);
                rlTmp.setColor((String) objects[3]);
                rlTmp.setScope((String) objects[4]);
                rlTmp.setEngine((String) objects[5]);
                rlTmp.setSensitive((Boolean) objects[6]);
                rl.add(rlTmp);
            }
            rlsTmp.setRule(rl);
            rls.add(rlsTmp);
        });
        con.setRules(rls);
        File f = new File(LoadConfig.getConfigPath());
        try{
            Writer ws = new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8);
            yaml.dump(con,ws);
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }

    public void edit(Vector data, int select, String type) {
        Config.ruleConfig.get(type)[select] = data.toArray();
        this.format();
    }

    public void add(Vector data, String type) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(Config.ruleConfig.get(type)));
        x.add(data.toArray());
        Config.ruleConfig.put(type,x.toArray(new Object[x.size()][]));
        this.format();
    }
    public void remove(int select,String type) {
        ArrayList<Object[]> x = new ArrayList<>(Arrays.asList(Config.ruleConfig.get(type)));
        x.remove(select);
        Config.ruleConfig.put(type,x.toArray(new Object[x.size()][]));
        this.format();
    }

    public void rename(String oldName, String newName) {
        Config.ruleConfig.put(newName, Config.ruleConfig.remove(oldName));
        this.format();
    }

    public void deleteRules(String Rules) {
        Config.ruleConfig.remove(Rules);
        this.format();
    }
    public String newRules() {
        int i = 0;
        String name = "New ";
        Object[][] data = new Object[][]{
                {
                    false, "New Name", "(New Regex)", "gray", "any", "nfa", false
                }
        };
        while (Config.ruleConfig.containsKey(name + i)) {
            i++;
        }
        Config.ruleConfig.put(name + i, data);
        this.format();
        return name + i;
    }
}
