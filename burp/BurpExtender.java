package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.util.*;

import org.json.*;

import burp.action.DoAction;
import burp.action.ExtractContent;
import burp.action.MatchHTTP;
import burp.color.GetColorKey;
import burp.color.UpgradeColor;
import burp.file.FileExists;
import burp.file.ReadFile;
import burp.file.RemoveContent;
import burp.file.WriteFile;
import burp.ui.FillTable;

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
import java.io.File;
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
	private static IExtensionHelpers helpers;
	private static String configFilePath = "config.json";
	private static String initFilePath = "init.hae";
	private static IMessageEditorTab HaETab;
	private static PrintWriter stdout;
	
	ReadFile rf = new ReadFile();
	WriteFile wfc = new WriteFile();
	FileExists fe = new FileExists();
	RemoveContent rc = new RemoveContent();
	GetColorKey gck = new GetColorKey();
	UpgradeColor uc = new UpgradeColor();
	ExtractContent ec = new ExtractContent();
	MatchHTTP mh = new MatchHTTP();
	FillTable ft = new FillTable();
	DoAction da = new DoAction();
	
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
    	this.callbacks = callbacks;
    BurpExtender.helpers = callbacks.getHelpers();
        // 设置插件名字和版本
    	String version = "1.5.1";

        callbacks.setExtensionName(String.format("HaE (%s) - Highlighter and Extractor", version));
        
        // 定义输出
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("@Author: EvilChen");
        stdout.println("@Blog: gh0st.cn");

        // UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// 判断"config.json"文件是否具备内容，如若不具备则进行初始化
				if (configFilePath.equals("config.json")) {
					if (rf.readFileContent(configFilePath).equals("")) {
						wfc.writeFileContent(configFilePath, Config.initConfigContent);
						wfc.writeFileContent(initFilePath, configFilePath);
					}
				}
				// 判断配置文件是否存在
				if (fe.fileExists(configFilePath)) {
					configFilePath = rf.readFileContent(initFilePath);
				} else {
					JOptionPane.showMessageDialog(null, "Config File Not Found!", "Error", JOptionPane.ERROR_MESSAGE);
				}
				
				initialize();
				ft.fillTable(configFilePath, table);
				
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
			    wfc.writeFileContent(initFilePath, configFilePath);
			    ft.fillTable(configFilePath, table);
			}
		});
		panel_3.add(btnNewButton);
		
		JPanel panel_2 = new JPanel();
		panel.add(panel_2, BorderLayout.CENTER);
		panel_2.setLayout(new BorderLayout(0, 0));
		
		JPanel panel_1 = new JPanel();
		panel_2.add(panel_1, BorderLayout.NORTH);
		panel_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null), "Actions", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		
		JButton btnReloadRule = new JButton("Reload");
		btnReloadRule.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				ft.fillTable(configFilePath, table);
			}
		});
		panel_1.add(btnReloadRule);
		
		JButton btnNewRule = new JButton("New");
		btnNewRule.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				DefaultTableModel dtm = (DefaultTableModel) table.getModel();
				Vector rules = new Vector();
				rules.add(true);
				rules.add("New Rule");
				rules.add("New Regex");
				rules.add("red");
				rules.add("response");
				rules.add("any");
				rules.add("nfa");
				dtm.addRow(rules);
				// 新增之后刷新Table，防止存在未刷新删除导致错位
				ft.fillTable(configFilePath, table);
			}
		});
		panel_1.add(btnNewRule);
		
		JButton btnDeleteRule = new JButton("Delete");
		btnDeleteRule.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectRows = table.getSelectedRows().length;
				DefaultTableModel dtm = (DefaultTableModel) table.getModel();
				if (selectRows == 1) {
					int selectedRowIndex = table.getSelectedRow();
					// 在配置文件中删除数据
					String cellValue = (String) dtm.getValueAt(selectedRowIndex, 1);
					// System.out.println(cellValue);
					rc.removeFileContent(cellValue, configFilePath);
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
				"Loaded", "Name", "Regex", "Color", "Scope", "Action", "Engine"
			}
		));
		scrollPane.setViewportView(table);
		
		table.getColumnModel().getColumn(2).setPreferredWidth(172);
		table.getColumnModel().getColumn(3).setCellEditor(new DefaultCellEditor(new JComboBox(Config.colorArray)));
		table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()));
		table.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(new JComboBox(Config.scopeArray)));
		table.getColumnModel().getColumn(5).setCellEditor(new DefaultCellEditor(new JComboBox(Config.actionArray)));
		table.getColumnModel().getColumn(6).setCellEditor(new DefaultCellEditor(new JComboBox(Config.engineArray)));
		
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
			    			jsonObj1.put("scope", (String) dtm.getValueAt(i, 4));
			    			jsonObj1.put("action", (String) dtm.getValueAt(i, 5));
			    			jsonObj1.put("engine", (String) dtm.getValueAt(i, 6));
			    			// 添加数据
			    			jsonObj.put((String) dtm.getValueAt(i, 1), jsonObj1);
						}
			    		
			    		wfc.writeFileContent(configFilePath, jsonObj.toString());
			    		
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
		if (toolFlag == 64 || toolFlag == 32 || toolFlag == 4) {
			JSONObject jsonObj = new JSONObject();
			byte[] content = messageInfo.getRequest();
            // 流量清洗
            String urlString = helpers.analyzeRequest(messageInfo.getHttpService(), content).getUrl().toString();
            urlString = urlString.indexOf("?") > 0 ? urlString.substring(0, urlString.indexOf("?")) : urlString;
            // 正则判断
            if (mh.matchSuffix(urlString)) {
				return;
			}
	        if (messageIsRequest) {
	            jsonObj = ec.matchRegex(content, "request", "highlight", configFilePath); 
	        } else {
	            content = messageInfo.getResponse();
	            // 流量清洗
	            List<String> mimeList = helpers.analyzeResponse(content).getHeaders();
	            // 正则判断
	            if (mh.matchMIME(mimeList)) {
					return;
				}
	            jsonObj = ec.matchRegex(content, "response", "highlight", configFilePath); 
	        }
	        
            List<String> colorList = da.highlightList(jsonObj);
            if (colorList.size() != 0) {
                String color = uc.getEndColor(gck.getColorKeys(colorList, Config.colorArray), Config.colorArray);;
                messageInfo.setHighlight(color);
            }
		}

    }
	
	class MarkInfoTab implements IMessageEditorTab {
		private ITextEditor markInfoText;
		private byte[] currentMessage;
		private final IMessageEditorController controller;
		private byte[] extractRequestContent;
		private byte[] extractResponseContent;
		
		public MarkInfoTab(IMessageEditorController controller, boolean editable) {
			this.controller = controller;
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
			try {
				// 流量清洗
	            String urlString = helpers.analyzeRequest(controller.getHttpService(), controller.getRequest()).getUrl().toString();
	            urlString = urlString.indexOf("?") > 0 ? urlString.substring(0, urlString.indexOf("?")) : urlString;
	            // 正则判断
	            if (mh.matchSuffix(urlString)) {
					return false;
				}
			} catch (Exception e) {
				return false;
			}
			
			if (isRequest) {
				JSONObject jsonObj = ec.matchRegex(content, "request", "extract", configFilePath);
				if (jsonObj.length() != 0) {
					String result = da.extractString(jsonObj);
					extractRequestContent = result.getBytes();
					return true;
				}
			} else {
				// 流量清洗
	            List<String> mimeList = helpers.analyzeResponse(controller.getResponse()).getHeaders();
	            // 正则判断
	            if (mh.matchMIME(mimeList)) {
					return false;
				}
				JSONObject jsonObj = ec.matchRegex(content, "response", "extract", configFilePath);
				if (jsonObj.length() != 0) {
					String result = da.extractString(jsonObj);
					extractResponseContent = result.getBytes();
					return true;
				}
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
			if (content.length > 0) {
				if (isRequest) {
					markInfoText.setText(extractRequestContent);
				} else {
					markInfoText.setText(extractResponseContent);
				}
			}
			currentMessage = content;
		}
	}
	
	
	
	public static void main(String[] args) {
	}
}