package burp;

/*
 * @author EvilChen
 */

public class Config {
    public static String excludeSuffix = "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|vsd|wav|weba|webm|webp|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd|zip|zip";

    public static String[] scopeArray = new String[] {
            "any",
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

    public static String outputTplString = "[%s]\n%s\n\n";

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
}