package burp.yaml;

import java.util.List;

/*
 * @author LinChen
 */

public class Config {
    public List<Rules> rules;

    public List<Rules> getRules() {
        return rules;
    }

    public void setRules(List<Rules> rules) {
        this.rules = rules;
    }
}
