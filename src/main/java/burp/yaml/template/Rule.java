package burp.yaml.template;

import java.util.HashMap;
import java.util.Map;

/*
 * @author LinChen
 */

public class Rule {
    private String Name;
    private Boolean Loaded;
    private String Regex;
    private String Color;
    private String Engine;
    private String Scope;

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

    public Object[] getRuleObject() {
        return new Object[] { Loaded, Name, Regex, Color, Scope, Engine };
    }

    public Map<String, Object> getRuleObjMap(){
        Map<String,Object> r = new HashMap<>();
        r.put("Loaded", Loaded);
        r.put("Name", Name);
        r.put("Regex", Regex);
        r.put("Color", Color);
        r.put("Scope", Scope);
        r.put("Engine", Engine);
        return r;
    }

    public String toString() {
        return "{ \nLoaded: " + Loaded + "\nName: " + Name + "\nRegex: " + Regex + "\nColor: " + Color + "\nScope: " + Scope + "\nEngine: " + Engine + "\n}";
    }
}