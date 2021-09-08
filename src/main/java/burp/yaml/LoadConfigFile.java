package burp.yaml;

import org.jetbrains.annotations.NotNull;
import org.yaml.snakeyaml.Yaml;

import burp.Config;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/*
 * @author LinChen
 */

public class LoadConfigFile {
    private static final Yaml yaml = new Yaml();
    private static final String SettingPath = "Setting.yml";
    private static final String ConfigPath = "Config.yml";

    public LoadConfigFile(){
        init();
    }

    // 初始化配置
    public void init(){
        File yamlSetting = new File(SettingPath);
        if (!(yamlSetting.exists() && yamlSetting.isFile())) {
            Map<String,Object> r = new HashMap<>();
            r.put("configPath", ConfigPath);
            r.put("excludeSuffix", getExcludeSuffix());
            try{
                Writer ws = new OutputStreamWriter(new FileOutputStream(SettingPath), StandardCharsets.UTF_8);
                yaml.dump(r, ws);
            }catch (Exception ex){
                ex.printStackTrace();
            }
        }
    }

    public String getExcludeSuffix(){
        try {
            InputStream inorder = new FileInputStream(SettingPath);
            Map<String,Object> r;
            r = yaml.load(inorder);
            return r.get("excludeSuffix").toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return Config.excludeSuffix;
        }
    }

    public static String getConfigPath(){
        try {
            InputStream inorder = new FileInputStream(SettingPath);
            Map<String,Object> r;
            r = yaml.load(inorder);
            return r.get("configPath").toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return ConfigPath;
        }
    }

    public void setExcludeSuffix(@NotNull String excludeSuffix){
        Map<String,Object> r = new HashMap<>();
        r.put("excludeSuffix", excludeSuffix);
        r.put("configPath", getConfigPath());
        try{
            Writer ws = new OutputStreamWriter(new FileOutputStream(SettingPath), StandardCharsets.UTF_8);
            yaml.dump(r, ws);
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }

    public void setConfigPath(@NotNull String filePath){
        Map<String,Object> r = new HashMap<>();
        r.put("configPath", filePath);
        r.put("excludeSuffix", getExcludeSuffix());
        try{
            Writer ws = new OutputStreamWriter(new FileOutputStream(SettingPath), StandardCharsets.UTF_8);
            yaml.dump(r, ws);
        }catch (Exception ex){
            ex.printStackTrace();
        }
    }
}
