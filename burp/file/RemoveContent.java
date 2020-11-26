package burp.file;

import javax.swing.JOptionPane;

import org.json.JSONObject;

public class RemoveContent {
	WriteFile w = new WriteFile();
	ReadFile r = new ReadFile();
	/*
	 * 删除某文件内容
	 */
	public void removeFileContent(String key, String configFilePath) {
		String jsonStr = r.readFileContent(configFilePath);
		JSONObject jsonObj = new JSONObject(jsonStr);
		jsonObj.remove(key);
		
		if (w.writeFileContent(configFilePath, jsonObj.toString())) {
			JOptionPane.showMessageDialog(null, "Delete Successfully!", "Info", JOptionPane.INFORMATION_MESSAGE);
		}
	}
}
