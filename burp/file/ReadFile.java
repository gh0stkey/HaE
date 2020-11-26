package burp.file;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class ReadFile {
	/*
	 * 获取文件内容
	 */
	public String readFileContent(String fileName) {
	    File file = new File(fileName);
	    BufferedReader reader = null;
	    StringBuffer sbf = new StringBuffer();
	    try {
	        reader = new BufferedReader(new FileReader(file));
	        String tempStr;
	        while ((tempStr = reader.readLine()) != null) {
	            sbf.append(tempStr);
	        }
	        reader.close();
	        return sbf.toString();
	    } catch (IOException e) {
	    } finally {
	        if (reader != null) {
	            try {
	                reader.close();
	            } catch (IOException err) {
	                err.printStackTrace();
	            }
	        }
	    }
	    return sbf.toString();
	}
}
