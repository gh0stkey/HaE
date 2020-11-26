package burp.action;

import java.util.Arrays;
import java.util.List;

import burp.Config;
import jregex.Matcher;
import jregex.Pattern;
import jregex.REFlags;

public class MatchHTTP {
	// 匹配后缀
	public boolean matchSuffix(String str) {
        Pattern pattern = new Pattern(String.format("[\\w]+[\\.](%s)", Config.excludeSuffix), REFlags.IGNORE_CASE);
        Matcher matcher = pattern.matcher(str);
        if(matcher.find()){
            return true;
        }else{
            return false;
        }
    }
	
	// 匹配MIME
	public boolean matchMIME(List<String> mimeList) {
		for (String headerString : mimeList) {
			if (headerString.toLowerCase().startsWith("content-type")) {
				for (String mime : Arrays.asList(Config.excludeMIME)) {
					if (headerString.contains(mime)) {
						return true;
					}
				}
			}
		}
		return false;
	}
}
