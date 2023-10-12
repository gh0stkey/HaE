package burp.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ConfigEntry {
    public static String excludeSuffix = "3g2|3gp|7z|aac|abw|aif|aifc|aiff|apk|arc|au|avi|azw|bat|bin|bmp|bz|bz2|cmd|cmx|cod|com|csh|css|csv|dll|doc|docx|ear|eot|epub|exe|flac|flv|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|less|m3u|mid|midi|mjs|mkv|mov|mp2|mp3|mp4|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogg|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|scss|sh|snd|svg|swf|tar|tif|tiff|ttf|vsd|war|wav|weba|webm|webp|wmv|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd|zip";

    public static String[] scopeArray = new String[] {
            "any",
            "any header",
            "any body",
            "response",
            "response header",
            "response body",
            "request",
            "request header",
            "request body"
    };

    public static String[] engineArray = new String[] {
            "nfa",
            "dfa"
    };

    public static String[] colorArray = new String[] {
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

    public static Map<String,Object[][]> globalRules = null;

    public static Map<String, Map<String, List<String>>> globalDataMap = new HashMap<>();
}