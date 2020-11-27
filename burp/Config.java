package burp;

public class Config {
	public static String initConfigContent = "{\"Email\":{\"loaded\":true,\"scope\":\"response\",\"regex\":\"([\\\\w-]+(?:\\\\.[\\\\w-]+)*@(?:[\\\\w](?:[\\\\w-]*[\\\\w])?\\\\.)+[\\\\w](?:[\\\\w-]*[\\\\w])?)\",\"action\":\"any\",\"color\":\"yellow\"}}";
	public static String[] colorArray = new String[] {"red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"};
	public static String[] scopeArray = new String[] {"any", "response", "request"};
	public static String[] actionArray = new String[] {"any", "extract", "highight"};
	public static String excludeSuffix = "7z|aif|aifc|aiff|au|bmp|cmx|cod|css|doc|docx|gif|gz|ico|ief|jfif|jpe|jpeg|jpg|m3u|mid|mp2|mp3|mpa|mpe|mpeg|mpg|mpp|mpv2|otf|pbm|pdf|pgm|png|pnm|ppm|ra|ram|rar|ras|rgb|rmi|snd|svg|tar|tif|tiff|ttf|wav|woff|woff2|xbm|xpm|xwd|zip";
	public static String[] excludeMIME = new String[] {"application/msword", "application/vnd.ms-project", "application/x-gzip", "application/x-tar", "application/zip", "audio/basic", "audio/mid", "audio/mpeg", "audio/x-aiff", "audio/x-mpegurl", "audio/x-pn-realaudio", "audio/x-wav", "image/bmp", "image/cis-cod", "image/gif", "image/ief", "image/jpeg", "image/png", "image/pipeg", "image/svg+xml", "image/tiff", "image/x-cmu-raster", "image/x-cmx", "image/x-icon", "image/x-portable-anymap", "image/x-portable-bitmap", "image/x-portable-graymap", "image/x-portable-pixmap", "image/x-rgb", "image/x-xbitmap", "image/x-xpixmap", "image/x-xwindowdump", "text/css", "video/mpeg", "video/mpeg", "application/font-woff"};
	public static String outputTplString = "[%s]\n%s\n\n";
}
