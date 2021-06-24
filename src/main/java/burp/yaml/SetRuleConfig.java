package burp.yaml;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.*;

public class SetRuleConfig {
    private static Yaml yaml;
    private static LoadConfigFile loadfile;
    private static LoadRule lr;
    private Map<String,Object[][]> config = lr.getConfig();
    public void format(){
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Representer representer = new Representer();
        representer.addClassTag(Config.class, Tag.MAP);
        yaml = new Yaml(new Constructor(),representer,dop);
        Config con = new Config();
        List<Rules> rls = new ArrayList<>();

        config.keySet().forEach(i->
        {
            Rules rlstmp = new Rules();
            rlstmp.setType(i);
            List<Rule> rl = new ArrayList<>();
            for (Object[] objects : config.get(i)) {
                Rule rltmp = new Rule();
                rltmp.setName((String) objects[1]);
                rltmp.setLoaded((Boolean) objects[0]);
                rltmp.setRegex((String) objects[2]);
                rltmp.setColor((String) objects[3]);
                rltmp.setScope((String) objects[4]);
                rltmp.setEngine((String) objects[5]);
                rl.add(rltmp);
            }
            rlstmp.setRule(rl);
            rls.add(rlstmp);
        });
        con.setRules(rls);
        File f = new File(loadfile.getConfigPath());
        try{
            Writer ws = new OutputStreamWriter(new FileOutputStream(f),"UTF-8");
            yaml.dump(con,ws);
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }
    public void edit(Vector data,int select, String type){
        loadfile = new LoadConfigFile();
        lr = new LoadRule(loadfile.getConfigPath());
        config = lr.getConfig();
        config.get(type)[select] = data.toArray();
        this.format();
    }
    public void add(Vector data,String type){
        loadfile = new LoadConfigFile();
        lr = new LoadRule(loadfile.getConfigPath());
        config = lr.getConfig();
        ArrayList<Object[]> x = new ArrayList<Object[]>(Arrays.asList(config.get(type)));
        x.add(data.toArray());
        config.put(type,x.toArray(new Object[x.size()][]));
        this.format();
    }
    public void remove(int select,String type){
        loadfile = new LoadConfigFile();
        lr = new LoadRule(loadfile.getConfigPath());
        config = lr.getConfig();
        ArrayList<Object[]> x = new ArrayList<Object[]>(Arrays.asList(config.get(type)));
        x.remove(select);
        config.put(type,x.toArray(new Object[x.size()][]));
        this.format();
    }
    public void rename(String oldname,String newname){
        loadfile = new LoadConfigFile();
        lr = new LoadRule(loadfile.getConfigPath());
        config = lr.getConfig();
        config.put(newname,config.remove(oldname));
        this.format();
    }
    public void deleteRules(String Rules){
        loadfile = new LoadConfigFile();
        lr = new LoadRule(loadfile.getConfigPath());
        config = lr.getConfig();
        config.remove(Rules);
        this.format();
    }
    public String newRules(){
        int i = 0;
        loadfile = new LoadConfigFile();
        lr = new LoadRule(loadfile.getConfigPath());
        config = lr.getConfig();
        String name = "New ";
        Object[][] data = new Object[][]{{false, "New Name", "(New Regex)", "gray", "any", "nfa"}};
        while (config.containsKey(name+i)){
            i++;
        }
        config.put(name+i,data);
        this.format();
        return name+i;
    }
}
