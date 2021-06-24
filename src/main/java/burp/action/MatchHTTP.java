package burp.action;

import jregex.Matcher;
import jregex.Pattern;
import jregex.REFlags;
import burp.yaml.LoadConfigFile;

/*
 * @author EvilChen
 */

public class MatchHTTP {
    // 匹配后缀
    LoadConfigFile lc = new LoadConfigFile();
    public boolean matchSuffix(String str) {
        Pattern pattern = new Pattern(String.format("[\\w]+[\\.](%s)", lc.getExcludeSuffix()), REFlags.IGNORE_CASE);
        Matcher matcher = pattern.matcher(str);
        if(matcher.find()){
            return true;
        }else{
            return false;
        }
    }
}
