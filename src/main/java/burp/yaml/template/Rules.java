package burp.yaml.template;

import burp.yaml.template.Rule;

import java.util.List;

/**
 * @author LinChen
 */

public class Rules {
    private String type;
    public List<Rule> rule;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<Rule> getRule() {
        return rule;
    }

    public void setRule(List<Rule> rule) {
        this.rule = rule;
    }

    public void setRuleObj(){}

    @Override
    public String toString(){
        return "{ type: "+type+"\n config: "+ rule +"}\n";
    }
}