package burp;

public class Config {
	public static String initConfigContent = "{\"Email\":{\"loaded\":true,\"scope\":\"response\",\"regex\":\"([\\\\w-]+(?:\\\\.[\\\\w-]+)*@(?:[\\\\w](?:[\\\\w-]*[\\\\w])?\\\\.)+[\\\\w](?:[\\\\w-]*[\\\\w])?)\",\"action\":\"any\",\"color\":\"yellow\", \"engine\":\"nfa\"}}";
	
	public static String[] colorArray = new String[] {"red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"};
	public static String[] scopeArray = new String[] {"any", "response", "request"};
	public static String[] actionArray = new String[] {"any", "extract", "highight"};
	public static String[] engineArray = new String[] {"nfa", "dfa"};
	
	public static String excludeSuffix = "3g2|3gp|7z|aac|abw|aif|aifc|aiff|arc|au|avi|azw|bin|bmp|bz|bz2|cmx|cod|csh|css|csv|doc|docx|eot|epub|gif|gz|ico|ics|ief|jar|jfif|jpe|jpeg|jpg|m3u|mid|midi|mjs|mp2|mp3|mpa|mpe|mpeg|mpg|mpkg|mpp|mpv2|odp|ods|odt|oga|ogv|ogx|otf|pbm|pdf|pgm|png|pnm|ppm|ppt|pptx|ra|ram|rar|ras|rgb|rmi|rtf|snd|svg|swf|tar|tif|tiff|ttf|txt|vsd|wav|weba|webm|webp|woff|woff2|xbm|xls|xlsx|xpm|xul|xwd|zip|zip";
	
	public static String[] excludeMIME = new String[] {"application/epub+zip", "application/font-woff", "application/java-archive", "application/msword", "application/octet-stream", "application/ogg", "application/pdf", "application/rtf", "application/vnd.amazon.ebook", "application/vnd.apple.installer+xml", "application/vnd.mozilla.xul+xml", "application/vnd.ms-excel", "application/vnd.ms-fontobject", "application/vnd.ms-powerpoint", "application/vnd.ms-project", "application/vnd.oasis.opendocument.presentation", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.text", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.visio", "application/x-7z-compressed", "application/x-abiword", "application/x-bzip", "application/x-bzip2", "application/x-csh", "application/x-freearc", "application/x-gzip", "application/x-rar-compressed", "application/x-shockwave-flash", "application/x-tar", "application/zip", "audio/3gpp", "audio/3gpp2", "audio/aac", "audio/basic", "audio/mid", "audio/midi audio/x-midi", "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm", "audio/x-aiff", "audio/x-mpegurl", "audio/x-pn-realaudio", "audio/x-wav", "font/otf", "font/ttf", "font/woff", "font/woff2", "image/bmp", "image/cis-cod", "image/gif", "image/ief", "image/jpeg", "image/pipeg", "image/png", "image/svg+xml", "image/tiff", "image/vnd.microsoft.icon", "image/webp", "image/x-cmu-raster", "image/x-cmx", "image/x-icon", "image/x-portable-anymap", "image/x-portable-bitmap", "image/x-portable-graymap", "image/x-portable-pixmap", "image/x-rgb", "image/x-xbitmap", "image/x-xpixmap", "image/x-xwindowdump", "text/calendar", "text/css", "text/csv", "video/3gpp", "video/3gpp2", "video/mpeg", "video/ogg", "video/webm", "video/x-msvideo"};
	
	public static String outputTplString = "[%s]\n%s\n\n";
}
