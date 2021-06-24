package burp.yaml;

import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.nodes.Tag;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/*
 * @author LinChen
 */

public class LoadRule {
    private static String filePath = "Config.yml";
    public LoadRule(String configfile){
        filePath = configfile;
        init();
    }

    // 初始化配置
    public void init(){
        File settingyaml = new File(filePath);
        if (!(settingyaml.exists() && settingyaml.isFile())){
            Map<String,Object[][]> r = new HashMap<>();
            Rule rule = new Rule();
            rule.setLoaded(true);
            rule.setName("Email");
            rule.setColor("yellow");
            rule.setEngine("nfa");
            rule.setScope("response");
            rule.setRegex("(([a-zA-Z0-9][_|\\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\\.])*[a-zA-Z0-9]+\\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,}))");
            Rules rules = new Rules();
            rules.setType("Basic Information");
            ArrayList<Rule> rl = new ArrayList<>();
            rl.add(rule);
            rules.setRule(rl);
            ArrayList<Rules> rls = new ArrayList<>();
            rls.add(rules);
            Config config = new Config();
            config.setRules(rls);

            DumperOptions dop = new DumperOptions();
            dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            Representer representer = new Representer();
            representer.addClassTag(Config.class, Tag.MAP);

            Yaml yaml = new Yaml(new Constructor(),representer,dop);
            LoadConfigFile loadfile = new LoadConfigFile();
            File f = new File(loadfile.getConfigPath());
            try{
                Writer ws = new OutputStreamWriter(new FileOutputStream(f),"UTF-8");
                yaml.dump(config,ws);
            }catch (Exception ex){
                ex.printStackTrace();
            }
        }
    }

    public static Map<String,Object[][]> getConfig(){
        InputStream inorder = null;
        {
            try {
                inorder = new FileInputStream(new File(filePath));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        Yaml yaml = new Yaml(new Constructor(Config.class));
        Config plugin = yaml.loadAs(inorder, Config.class);
        Map<String,Object[][]> config = new HashMap<>();
        plugin.rules.forEach(i->{
            ArrayList<Object[]> data = new ArrayList<>();
            i.rule.forEach(j->{
                try {
                    data.add(j.getRuleObject());
                }catch (Exception e){
                    e.printStackTrace();
                }
            });
            config.put(i.getType(), data.toArray(new Object[data.size()][]));
        });
        return config;
    }
}
