package burp.file;

import java.io.File;

public class FileExists {
	
	/*
	 * 判断文件是否存在
	 */
	public Boolean fileExists(String fileName) {
		 File file = new File(fileName);
		 if(file.exists()){
			 return true;
		 }
		 return false;
	}
	
}
