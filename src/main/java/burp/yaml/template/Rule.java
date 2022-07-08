package burp.yaml.template;

import java.util.HashMap;
import java.util.Map;

/**
 * @author LinChen
 */

public class Rule {
    private String Name;
    private Boolean Loaded;
    private String Regex;
    private String Color;
    private String Engine;
    private String Scope;
    private Boolean Sensitive;

    public Boolean getLoaded() {
        return Loaded;
    }
    public String getColor() {
        return Color;
    }

    public String getEngine() {
        return Engine;
    }

    public String getName() {
        return Name;
    }

    public String getRegex() {
        return Regex;
    }

    public String getScope() {
        return Scope;
    }

    public Boolean getSensitive(){
        return Sensitive = Sensitive;
    }
    public void setLoaded(Boolean loaded) {
        this.Loaded = loaded;
    }


    public void setColor(String color) {
        this.Color = color;
    }

    public void setEngine(String engine) {
        this.Engine = engine;
    }

    public void setName(String name) {
        this.Name = name;
    }

    public void setRegex(String regex) {
        this.Regex = regex;
    }

    public void setScope(String scope) {
        this.Scope = scope;
    }
    public void setSensitive(Boolean sensitive){
        this.Sensitive = sensitive;
    }

    public Object[] getRuleObject() {
        return new Object[] { Loaded, Name, Regex, Color, Scope, Engine,Sensitive };
    }

    public Map<String, Object> getRuleObjMap(){
        Map<String,Object> r = new HashMap<>();
        r.put("Loaded", Loaded);
        r.put("Name", Name);
        r.put("Regex", Regex);
        r.put("Color", Color);
        r.put("Scope", Scope);
        r.put("Engine", Engine);
        r.put("Sensitive", Sensitive);
        return r;
    }

    @Override
    public String toString() {
        return "{ \nLoaded: " + Loaded + "\nName: " + Name + "\nRegex: " + Regex + "\nColor: " + Color + "\nScope: " + Scope + "\nEngine: " + Engine + "\nSensitive: " + Sensitive + "\n }";
    }
}