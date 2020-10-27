package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.*;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.DefaultCellEditor;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;
import javax.swing.JPanel;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.awt.event.ActionEvent;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.JLabel;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory, ITab {
	
	private JFrame frame;
	private JPanel panel;
	private JTable table;
	private JTextField textField;
	private IBurpExtenderCallbacks callbacks;
	private static String configFilePath = "config.json";
	private static String initFilePath = "init.hae";
	private static String initConfigContent = "{\"Email\":{\"loaded\":true,\"highlight\":true,\"regex\":\"([\\\\w-]+(?:\\\\.[\\\\w-]+)*@(?:[\\\\w](?:[\\\\w-]*[\\\\w])?\\\\.)+[\\\\w](?:[\\\\w-]*[\\\\w])?)\",\"extract\":true,\"color\":\"yellow\"}}";
	private static String endColor = "";
	private static String[] colorArray = new String[] {"red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"};
	private static IMessageEditorTab HaETab;
	private static PrintWriter stdout;
	
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
    	this.callbacks = callbacks;
        // 设置插件名字
        callbacks.setExtensionName("HaE - Highlighter and Extractor");
        
        // 定义输出
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("@Author: EvilChen");

        // UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// 判断"config.json"文件是否具备内容，如若不具备则进行初始化
				if (configFilePath.equals("config.json")) {
					if (readFileContent(configFilePath).equals("")) {
						writeFileContent(configFilePath, initConfigContent);
						writeFileContent(initFilePath, configFilePath);
					}
				}
				// 判断配置文件是否存在
				if (fileExists(configFilePath)) {
					configFilePath = readFileContent(initFilePath);
				} else {
					JOptionPane.showMessageDialog(null, "Config File Not Found!", "Error", JOptionPane.ERROR_MESSAGE);
				}
				
				initialize();
				fillTable();
				
			}
		});
		callbacks.registerHttpListener(BurpExtender.this);
		callbacks.registerMessageEditorTabFactory(BurpExtender.this);
    }
    
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 526, 403);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		panel = new JPanel();
		frame.getContentPane().add(panel, BorderLayout.CENTER);
		panel.setLayout(new BorderLayout(0, 0));
		
		JPanel panel_3 = new JPanel();
		panel.add(panel_3, BorderLayout.NORTH);
		
		JLabel lblNewLabel_1 = new JLabel("Config File:");
		panel_3.add(lblNewLabel_1);
		
		textField = new JTextField();
		textField.setEditable(false);
		panel_3.add(textField);
		textField.setColumns(20);
		
		textField.setText(configFilePath);
		
		JButton btnNewButton = new JButton("Select File ...");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
			    JFileChooser jfc = new JFileChooser();
			    jfc.setFileSelectionMode(JFileChooser.FILES_ONLY);
			    jfc.showDialog(new JLabel(), "Choose");
			    File file = jfc.getSelectedFile();
			    textField.setText(file.getAbsolutePath());
			    configFilePath = textField.getText();
			    writeFileContent(initFilePath, configFilePath);
			    fillTable();
			}
		});
		panel_3.add(btnNewButton);
		
		JPanel panel_2 = new JPanel();
		panel.add(panel_2, BorderLayout.CENTER);
		panel_2.setLayout(new BorderLayout(0, 0));
		
		JPanel panel_1 = new JPanel();
		panel_2.add(panel_1, BorderLayout.NORTH);
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Actions", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		
		JButton btnReloadRule = new JButton("Reload Rule");
		btnReloadRule.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				fillTable();
			}
		});
		panel_1.add(btnReloadRule);
		
		JButton btnNewRule = new JButton("New Rule");
		btnNewRule.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				DefaultTableModel dtm = (DefaultTableModel) table.getModel();
				Vector rules = new Vector();
				rules.add(true);
				rules.add("New Rule");
				rules.add("New Regex");
				rules.add("red");
				rules.add(true);
				rules.add(true);
				dtm.addRow(rules);
			}
		});
		panel_1.add(btnNewRule);
		
		JButton btnDeleteRule = new JButton("Delete Rule");
		btnDeleteRule.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectRows = table.getSelectedRows().length;
				DefaultTableModel dtm = (DefaultTableModel) table.getModel();
				if (selectRows == 1) {
					int selectedRowIndex = table.getSelectedRow();
					// 在配置文件中删除数据
					String cellValue = (String) dtm.getValueAt(selectedRowIndex, 1);
					// System.out.println(cellValue);
					removeConfig(cellValue);
					// 在表格中删除数据
					dtm.removeRow(selectedRowIndex);
					
				}
			}
		});
		panel_1.add(btnDeleteRule);
		
		JScrollPane scrollPane = new JScrollPane();
		panel_2.add(scrollPane, BorderLayout.CENTER);
		
		table = new JTable();
		table.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"Loaded", "Name", "Regex", "Color", "isExtract", "isHighlight"
			}
		));
		scrollPane.setViewportView(table);
		
		table.getColumnModel().getColumn(2).setPreferredWidth(172);
		table.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(new JComboBox(colorArray)));
		table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()));
		table.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(new JCheckBox()));
		table.getColumnModel().getColumn(5).setCellEditor(new DefaultCellEditor(new JCheckBox()));
		
		JLabel lblNewLabel = new JLabel("@EvilChen Love YuChen.");
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(lblNewLabel, BorderLayout.SOUTH);
		
		table.getModel().addTableModelListener(
			new TableModelListener() {
			    @Override
			    public void tableChanged(TableModelEvent e) {
			    	if (e.getType() == TableModelEvent.INSERT || e.getType() == TableModelEvent.UPDATE) {
			    		DefaultTableModel dtm = (DefaultTableModel) table.getModel();
			    		int rows = dtm.getRowCount();
			    		JSONObject jsonObj = new JSONObject();
			    		
			    		for (int i = 0; i < rows; i++) {
			    			JSONObject jsonObj1 = new JSONObject();
			    			jsonObj1.put("loaded", (boolean) dtm.getValueAt(i, 0));
			    			jsonObj1.put("regex", (String) dtm.getValueAt(i, 2));
			    			jsonObj1.put("color", (String) dtm.getValueAt(i, 3));
			    			jsonObj1.put("extract", (boolean) dtm.getValueAt(i, 4));
			    			jsonObj1.put("highlight", (boolean) dtm.getValueAt(i, 5));
			    			// 添加数据
			    			jsonObj.put((String) dtm.getValueAt(i, 1), jsonObj1);
						}
			    		
			    		writeFileContent(configFilePath, jsonObj.toString());
			    		
			    	}
						
			    }
			}
		);
		callbacks.customizeUiComponent(panel);
		callbacks.customizeUiComponent(panel_1);
		callbacks.customizeUiComponent(panel_2);
		callbacks.customizeUiComponent(panel_3);
		callbacks.customizeUiComponent(scrollPane);
		callbacks.addSuiteTab(BurpExtender.this);
		
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		HaETab = new MarkInfoTab(controller, editable);
		return HaETab;
	}
    
	@Override
	public String getTabCaption() {
		return "HaE";
	}

	@Override
	public Component getUiComponent() {
		return panel;
	}
	
	/*
	 * 使用processHttpMessage用来做Highlighter
	 */
	@Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// 判断是否是响应，且该代码作用域为：REPEATER、INTRUDER、PROXY（分别对应toolFlag 64、32、4）
        if (!messageIsRequest && (toolFlag == 64 || toolFlag == 32 || toolFlag == 4)) {
            byte[] content = messageInfo.getResponse();
            try {
				String c = new String(content, "UTF-8").intern();
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
            JSONObject jsonObj = matchRegex(content);
            if (jsonObj.length() > 0) {
                List<String> colorList = new ArrayList<String>();
                Iterator<String> k = jsonObj.keys();
                while (k.hasNext()) {
                    String name = k.next();
                    JSONObject jsonObj2 = new JSONObject(jsonObj.get(name).toString());
                    boolean isHighlight = jsonObj2.getBoolean("highlight");
                    if (isHighlight) {
                        colorList.add(jsonObj2.getString("color"));
                    }
                }
                if (colorList.size() != 0) {
                	colorUpgrade(getColorKeys(colorList));
                    String color = endColor;
                    messageInfo.setHighlight(color);
                }
            }
        }
    }
	
	class MarkInfoTab implements IMessageEditorTab {
		private ITextEditor markInfoText;
		private byte[] currentMessage;
	
		public MarkInfoTab(IMessageEditorController controller, boolean editable) {
			markInfoText = callbacks.createTextEditor();
			markInfoText.setEditable(editable);
		}
	
		@Override
		public String getTabCaption() {
			return "MarkInfo";
		}
	
		@Override
		public Component getUiComponent() {
			return markInfoText.getComponent();
		}
	
		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
			// 先判断是否是请求，再判断是否匹配到内容
			if (!isRequest && matchRegex(content).length() != 0) {
				return true;
			}
			return false;
		}
	
		@Override
		public byte[] getMessage() {
			return currentMessage;
		}
	
		@Override
		public boolean isModified() {
			return markInfoText.isTextModified();
		}
	
		@Override
		public byte[] getSelectedData() {
			return markInfoText.getSelectedText();
		}
		
		/*
		 * 使用setMessage用来做Extractor
		 */
		@Override
		public void setMessage(byte[] content, boolean isRequest) {
			try {
				String c = new String(content, "UTF-8").intern();
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			if (content.length > 0 && !isRequest) {
				String result = "";
				JSONObject jsonObj = matchRegex(content);
				if (jsonObj.length() != 0) {
					Iterator<String> k = jsonObj.keys();
					while (k.hasNext()) {
						String name = k.next();
						JSONObject jsonObj1 = new JSONObject(jsonObj.get(name).toString());
						boolean isExtract = jsonObj1.getBoolean("extract");
						if (isExtract) {
							String tmpStr = String.format("[%s]\n%s\n\n", name, jsonObj1.getString("data")).intern();
							result += tmpStr;
						}
					}
				}
		        markInfoText.setText(result.getBytes());
			}
			currentMessage = content;
		}
	}
	

	private JSONObject matchRegex(byte[] content) {
		JSONObject tabContent = new JSONObject();
		// 正则匹配提取内容
		try {
			String jsonStr = readFileContent(configFilePath);
		    JSONObject jsonObj = new JSONObject(jsonStr);
		    Iterator<String> k = jsonObj.keys();
		    // 遍历json数组
		    while (k.hasNext()) {
		    	String contentString = new String(content, "UTF-8").intern();
		    	String name = k.next(); 
		    	JSONObject jsonObj1 = new JSONObject(jsonObj.get(name).toString());
		    	JSONObject jsonData = new JSONObject();
				String regex = jsonObj1.getString("regex");
				boolean isHighligth = jsonObj1.getBoolean("highlight");
				boolean isExtract = jsonObj1.getBoolean("extract");
				boolean isLoaded = jsonObj1.getBoolean("loaded");
				String color = jsonObj1.getString("color");
				List<String> result = new ArrayList<String>();
				if(isLoaded) {
					Pattern pattern = Pattern.compile(regex);
					Matcher matcher = pattern.matcher(contentString);
					while (matcher.find()) {
						// 添加匹配数据至list
						// 强制用户使用()包裹正则
						result.add(matcher.group(1));
					}
					// 去除重复内容
					HashSet tmpList = new HashSet(result);
					result.clear();
					result.addAll(tmpList);
					
					if (!result.isEmpty()) {
						jsonData.put("highlight", isHighligth);
						jsonData.put("extract", isExtract);
						jsonData.put("color", color);
						jsonData.put("data", String.join("\n", result));
						jsonData.put("loaded", isLoaded);
						// 初始化格式
						tabContent.put(name, jsonData);
					}
				}

		    }
		    return tabContent;
		} catch (Exception e) {
			return new JSONObject();
		}

	}

	/*
	 * 颜色下标获取
	 */
	private List<Integer> getColorKeys(List<String> keys){
		List<Integer> result = new ArrayList<Integer>();
		int size = colorArray.length;
		// 根据颜色获取下标
		for (int x = 0; x < keys.size(); x++) {
			for (int v = 0; v < size; v++) {
				if (colorArray[v].equals(keys.get(x))) {
					result.add(v);
				}
			}
		}
		return result;
	}
	
	/*
	 * 颜色升级递归算法
	 */
	private static String colorUpgrade(List<Integer> colorList) {
		int colorSize = colorList.size();
		colorList.sort(Comparator.comparingInt(Integer::intValue));
		int i = 0;
		List<Integer> stack = new ArrayList<Integer>();
		while (i < colorSize) {
			if (stack.isEmpty()) {
				stack.add(colorList.get(i));
				i++;
			} else {
				if (colorList.get(i) != stack.stream().reduce((first, second) -> second).orElse(99999999)) {
					stack.add(colorList.get(i));
					i++;
				} else {
					stack.set(stack.size() - 1, stack.get(stack.size() - 1) - 1);
					i++;
				}
			}
			
		}
		// 利用HashSet删除重复元素
		HashSet tmpList = new HashSet(stack);
		if (stack.size() == tmpList.size()) {
			stack.sort(Comparator.comparingInt(Integer::intValue));
			if(stack.get(0).equals(-1)) {
				endColor = colorArray[0];
			} else {
				endColor = colorArray[stack.get(0)];
			}
		} else {
			colorUpgrade(stack);
		}
		return "";
	}
	
	/*
	 * 判断文件是否存在
	 */
	private Boolean fileExists(String fileName) {
		 File file = new File(fileName);
		 if(file.exists()){
			 return true;
		 }
		 return false;
	}
	/*
	 * 获取文件内容
	 */
	private String readFileContent(String fileName) {
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
	
	/*
	 * 写入文件内容
	 */
	private boolean writeFileContent(String fileName, String fileContent) {
		try {
			BufferedWriter out = new BufferedWriter(new FileWriter(fileName));
			out.write(fileContent);
			out.close();
			return true;
		} catch (IOException e) {
			stdout.println(e);
			return false;
		}
	}
	
	/*
	 * 删除单条配置内容
	 */
	private void removeConfig(String key) {
		String jsonStr = readFileContent(configFilePath);
		JSONObject jsonObj = new JSONObject(jsonStr);
		jsonObj.remove(key);
		if (writeFileContent(configFilePath, jsonObj.toString())) {
			JOptionPane.showMessageDialog(null, "Delete Successfully!", "Info", JOptionPane.INFORMATION_MESSAGE);
		}
	}
	
	/*
	 * 初始化表格内容
	 */
	private void fillTable() {
		DefaultTableModel dtm=(DefaultTableModel) table.getModel();
		dtm.setRowCount(0);
        String jsonStr = readFileContent(configFilePath);
        JSONObject jsonObj = new JSONObject(jsonStr);
        Iterator<String> k = jsonObj.keys();
        // 遍历json数组
        while (k.hasNext()) {
        	String name = k.next(); 
        	JSONObject jsonObj1 = new JSONObject(jsonObj.get(name).toString());
			boolean loaded = jsonObj1.getBoolean("loaded");
			String regex = jsonObj1.getString("regex");
			String color = jsonObj1.getString("color");
			boolean isExtract = jsonObj1.getBoolean("extract");
			boolean isHighlight = jsonObj1.getBoolean("highlight");
			// 填充数据
			Vector rules = new Vector();
			rules.add(loaded);
			rules.add(name);
			rules.add(regex);
			rules.add(color);
			rules.add(isExtract);
			rules.add(isHighlight);
			dtm.addRow(rules);
		}
	}
	
	public static void main(String[] args) {
	}
}