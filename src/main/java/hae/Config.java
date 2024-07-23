package hae;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Config {
    public static String suffix = "3g2|3gp|7z|aac|abw|aif|aifc|aiff|apk|arc|au|avi|azw|bat|bin|bmp|bz|bz2|cmd|cmx|cod|com|csh|css|csv|dll|doc|docx|ear|eot|epub|exe|flac|flv|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|less|m3u|mid|midi|mjs|mkv|mov|mp2|mp3|mp4|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogg|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|scss|sh|snd|svg|swf|tar|tif|tiff|ttf|vsd|war|wav|weba|webm|webp|wmv|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd|zip";

    public static String host = "gh0st.cn";

    public static String[] scope = new String[]{
            "any",
            "any header",
            "any body",
            "response",
            "response line",
            "response header",
            "response body",
            "request",
            "request line",
            "request header",
            "request body"
    };

    public static String scopeOptions = "Suite|Target|Proxy|Scanner|Intruder|Repeater|Logger|Sequencer|Decoder|Comparer|Extensions|Organizer|Recorded login replayer";

    public static String[] ruleFields = {
            "Loaded", "Name", "F-Regex", "S-Regex", "Format", "Color", "Scope", "Engine", "Sensitive"
    };

    public static Object[][] ruleTemplate = new Object[][]{
            {
                    false, "New Name", "(First Regex)", "(Second Regex)", "{0}", "gray", "any", "nfa", false
            }
    };

    public static String[] engine = new String[]{
            "nfa",
            "dfa"
    };

    public static String[] color = new String[]{
            "red",
            "orange",
            "yellow",
            "green",
            "cyan",
            "blue",
            "pink",
            "magenta",
            "gray"
    };

    public static String prompt = "You are a data security expert in the field of cyber security. Your task is to optimize the information provided by the user and then output it in JSON format. The user-supplied information is data that has been extracted by regular expressions. The user-supplied information is divided into two parts, the first part is RuleName which represents the name of the regular expression and the second part is MarkInfo which represents the data extracted by the regular expression. You need to find the matching or similar data in MarkInfo according to the meaning of RuleName, and output the original rows of these data in JSON format.(garbled and meaningless data rows should be removed)\n" +
            "You must ensure that the extracted data is accurately expressed and correctly formatted in the JSON structure. Your output data must comply with the original MarkInfo content rows without modification, and strictly adhere to the following JSON format for return, no other text, code and formatting (e.g., line breaks, carriage returns, indentation, spaces), once the return of other irrelevant content will cause irreparable damage to the user: {\"data\":[\"data1\", \"data2\"]}.";

    public static String userTextFormat = "User Input: \r\nRuleName: %s\r\nMarkInfo: %s";

    public static Map<String, Object[][]> globalRules = new HashMap<>();

    public static ConcurrentHashMap<String, Map<String, List<String>>> globalDataMap = new ConcurrentHashMap<>();
}
