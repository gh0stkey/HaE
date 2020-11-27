package burp.file;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class WriteFile {
	/*
	 * 写入文件内容
	 */
	public boolean writeFileContent(String fileName, String fileContent) {
		try {
			BufferedWriter out = new BufferedWriter(new FileWriter(fileName));
			out.write(fileContent);
			out.close();
			return true;
		} catch (IOException e) {
			return false;
		}
	}
}
