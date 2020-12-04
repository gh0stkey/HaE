package burp.ui;

import java.util.Iterator;
import java.util.Vector;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.json.JSONObject;

import burp.file.ReadFile;

public class FillTable {
	ReadFile rf = new ReadFile();
	/*
	 * 初始化表格内容
	 */
	public void fillTable(String configFilePath, JTable table) {
		DefaultTableModel dtm=(DefaultTableModel) table.getModel();
		dtm.setRowCount(0);
        String jsonStr = rf.readFileContent(configFilePath);
        JSONObject jsonObj = new JSONObject(jsonStr);
        Iterator<String> k = jsonObj.keys();
        // 遍历json数组
        while (k.hasNext()) {
        	String name = k.next(); 
        	JSONObject jsonObj1 = new JSONObject(jsonObj.get(name).toString());
			boolean loaded = jsonObj1.getBoolean("loaded");
			String regex = jsonObj1.getString("regex");
			String color = jsonObj1.getString("color");
			String scope = jsonObj1.getString("scope");
			String action = jsonObj1.getString("action");
			String engine = jsonObj1.getString("engine");
			// 填充数据
			Vector rules = new Vector();
			rules.add(loaded);
			rules.add(name);
			rules.add(regex);
			rules.add(color);
			rules.add(scope);
			rules.add(action);
			rules.add(engine);
			dtm.addRow(rules);
		}
	}
}
