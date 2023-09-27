package burp.ui;

import burp.Config;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import javax.swing.table.DefaultTableModel;
import org.jetbrains.annotations.NotNull;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.Map;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * @author LinChen && EvilChen
 */

public class Databoard extends JPanel {
    public Databoard() {
        initComponents();
    }

    /**
     * 清空数据
     */
    private void clearActionPerformed(ActionEvent e) {
        // 清空页面
        dataTabbedPane.removeAll();
        String host = hostTextField.getText();
        if (host.contains("*")) {
            Map<String, Map<String, List<String>>> ruleMap = Config.globalDataMap;
            ruleMap.keySet().forEach(i -> {
                if (i.contains(host.replace("*.", "")) || host.equals("*")) {
                    Config.globalDataMap.remove(i);
                }
            });
        } else {
            Config.globalDataMap.remove(host);
        }
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        hostLabel = new JLabel();
        hostTextField = new JTextField();
        dataTabbedPane = new JTabbedPane();
        clearButton = new JButton();

        //======== this ========
        setLayout(new GridBagLayout());
        ((GridBagLayout)getLayout()).columnWidths = new int[] {25, 0, 0, 0, 20, 0};
        ((GridBagLayout)getLayout()).rowHeights = new int[] {0, 65, 20, 0};
        ((GridBagLayout)getLayout()).columnWeights = new double[] {0.0, 0.0, 1.0, 0.0, 0.0, 1.0E-4};
        ((GridBagLayout)getLayout()).rowWeights = new double[] {0.0, 1.0, 0.0, 1.0E-4};

        //---- hostLabel ----
        hostLabel.setText("Host:");
        add(hostLabel, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(hostTextField, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        clearButton.setText("Clear");
        clearButton.addActionListener(this::clearActionPerformed);
        add(clearButton,  new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(dataTabbedPane, new GridBagConstraints(1, 1, 3, 2, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 0, 5), 0, 0));

        setAutoMatch(hostTextField, dataTabbedPane);
    }

    /**
     * 获取Host列表
     */
    private static List<String> getHostByList(){
        List<String> hostList = new ArrayList<>();
        hostList.addAll(Config.globalDataMap.keySet());
        return hostList;
    }

    /**
     * 设置输入自动匹配
     */
    public static void setAutoMatch(JTextField textField, JTabbedPane tabbedPane) {
        final DefaultComboBoxModel comboBoxModel = new DefaultComboBoxModel();

        final JComboBox hostComboBox = new JComboBox(comboBoxModel) {
            @Override
            public Dimension getPreferredSize() {
                return new Dimension(super.getPreferredSize().width, 0);
            }
        };

        isMatchHost = false;

        for (String host : getHostByList()) {
            comboBoxModel.addElement(host);
        }

        hostComboBox.setSelectedItem(null);

        hostComboBox.addActionListener(e -> {
            if (!isMatchHost) {
                if (hostComboBox.getSelectedItem() != null) {
                    textField.setText(hostComboBox.getSelectedItem().toString());
                    getInfoByHost(hostComboBox, tabbedPane, textField);
                }
            }
        });

        // 事件监听
        textField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                isMatchHost = true;
                if (e.getKeyCode() == KeyEvent.VK_SPACE) {
                    if (hostComboBox.isPopupVisible()) {
                        e.setKeyCode(KeyEvent.VK_ENTER);
                    }
                }
                if (e.getKeyCode() == KeyEvent.VK_ENTER
                        || e.getKeyCode() == KeyEvent.VK_UP
                        || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    e.setSource(hostComboBox);
                    hostComboBox.dispatchEvent(e);
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        textField.setText(hostComboBox.getSelectedItem().toString());
                        getInfoByHost(hostComboBox, tabbedPane, textField);
                        hostComboBox.setPopupVisible(false);
                    }
                }
                if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    hostComboBox.setPopupVisible(false);
                }
                isMatchHost = false;
            }
        });

        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateList();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateList();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                updateList();
            }

            private void updateList() {
                isMatchHost = true;
                comboBoxModel.removeAllElements();
                String input = textField.getText();
                if (!input.isEmpty()){
                    for (String host : getHostByList()) {
                        if (host.toLowerCase().contains(input.toLowerCase())) {
                            if (host.length() == input.length()){
                                comboBoxModel.insertElementAt(host,0);
                                comboBoxModel.setSelectedItem(host);
                            }else{
                                comboBoxModel.addElement(host);
                            }
                        }
                    }
                }
                hostComboBox.setPopupVisible(comboBoxModel.getSize() > 0);
                isMatchHost = false;
            }
        });

        textField.setLayout(new BorderLayout());
        textField.add(hostComboBox, BorderLayout.SOUTH);
    }

    private static void getInfoByHost(@NotNull JComboBox hostComboBox, JTabbedPane tabbedPane, JTextField textField) {
        if (hostComboBox.getSelectedItem() != null) {
            Map<String, Map<String, List<String>>> ruleMap = Config.globalDataMap;
            Map<String, List<String>> selectHost = new HashMap<>();
            String host = hostComboBox.getSelectedItem().toString();
            if (host.contains("*")) {
                // 通配符数据
                Map<String, List<String>> finalSelectHost = selectHost;
                ruleMap.keySet().forEach(i -> {
                    if (i.contains(host.replace("*.", "")) || host.equals("*")) {
                        ruleMap.get(i).keySet().forEach(e -> {
                            if (finalSelectHost.containsKey(e)) {
                                // 合并操作
                                List<String> newList = new ArrayList<>(finalSelectHost.get(e));
                                newList.addAll(ruleMap.get(i).get(e));
                                // 去重操作
                                HashSet tmpList = new HashSet(newList);
                                newList.clear();
                                newList.addAll(tmpList);
                                // 添加操作
                                finalSelectHost.put(e, newList);
                            } else {
                                finalSelectHost.put(e, ruleMap.get(i).get(e));
                            }
                        });
                    }
                });
            } else {
                selectHost = ruleMap.get(host);
            }

            tabbedPane.removeAll();
            for(Map.Entry<String, List<String>> entry: selectHost.entrySet()){
                tabbedPane.addTab(entry.getKey(), new JScrollPane(new HitRuleDataList(entry.getValue())));
            }
            textField.setText(hostComboBox.getSelectedItem().toString());
        }
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    private JLabel hostLabel;
    private JTextField hostTextField;
    private JTabbedPane dataTabbedPane;
    private JButton clearButton;
    // JFormDesigner - End of variables declaration  //GEN-END:variables

    // 是否自动匹配Host
    private static Boolean isMatchHost = false;
}
class HitRuleDataList extends JTable {
    public HitRuleDataList(List<String> list){
        DefaultTableModel model = new DefaultTableModel();
        Object[][] data = new Object[list.size()][1];
        for (int x = 0; x < list.size(); x++) {
            data[x][0] = list.get(x);
        }
        model.setDataVector(data, new Object[]{"Information"});
        this.setAutoCreateRowSorter(true);
        this.setModel(model);
    }
}
