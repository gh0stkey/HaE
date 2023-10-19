package burp.core.utils;

import jregex.Pattern;
import jregex.REFlags;
import burp.config.ConfigLoader;

/**
 * @author EvilChen
 */

public class MatchTool {
    public boolean matchUrlSuffix(String str) {
        Pattern pattern = new Pattern(String.format("[\\w]+[\\.](%s)", ConfigLoader.getExcludeSuffix()), REFlags.IGNORE_CASE);
        jregex.Matcher matcher = pattern.matcher(str);
        return matcher.find();
    }

    public static boolean matchIP(String str) {
        return str.matches("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    }
}
