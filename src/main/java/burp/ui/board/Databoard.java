package burp.ui.board;

import burp.config.ConfigEntry;
import burp.core.utils.StringHelper;
import burp.ui.board.MessagePanel.Table;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.swing.event.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import javax.swing.*;

/**
 * @author LinChen && EvilChen
 */

public class Databoard extends JPanel {
    private static Boolean isMatchHost = false;
    private JLabel hostLabel;
    private JTextField hostTextField;
    private JTabbedPane dataTabbedPane;
    private JButton clearButton;
    private JSplitPane splitPane;
    private MessagePanel messagePanel;
    private Table table;
    private SwingWorker<Object, Void> currentWorker;
    private DefaultComboBoxModel comboBoxModel = new DefaultComboBoxModel();
    private JComboBox hostComboBox = new JComboBox(comboBoxModel);
    private ChangeListener changeListenerInstance = new ChangeListener() {
        @Override
        public void stateChanged(ChangeEvent e) {
            int selectedIndex = dataTabbedPane.getSelectedIndex();
            String selectedTitle = "";

            if (selectedIndex != -1) {
                selectedTitle = dataTabbedPane.getTitleAt(selectedIndex);
            }

            applyHostFilter(selectedTitle);
        }
    };

    public Databoard(MessagePanel messagePanel) {
        this.messagePanel = messagePanel;
        initComponents();
    }

    private void cleanUI() {
        dataTabbedPane.removeAll();
        splitPane.setVisible(false);
    }

    private void clearActionPerformed(ActionEvent e) {
        int retCode = JOptionPane.showConfirmDialog(null, "Do you want to clear data?", "Info",
                JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            cleanUI();

            String host = hostTextField.getText();
            String cleanedHost = StringHelper.replaceFirstOccurrence(host, "*.", "");

            if (host.contains("*")) {
                ConfigEntry.globalDataMap.keySet().removeIf(i -> i.contains(cleanedHost) || cleanedHost.contains("*"));
            } else {
                ConfigEntry.globalDataMap.remove(host);
            }

            messagePanel.deleteByHost(cleanedHost);
        }
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        hostLabel = new JLabel();
        hostTextField = new JTextField();
        dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);
        clearButton = new JButton();

        //======== this ========
        setLayout(new GridBagLayout());
        ((GridBagLayout)getLayout()).columnWidths = new int[] {25, 0, 0, 0, 20, 0};
        ((GridBagLayout)getLayout()).rowHeights = new int[] {0, 65, 20, 0};
        ((GridBagLayout)getLayout()).columnWeights = new double[] {0.0, 0.0, 1.0, 0.0, 0.0, 1.0E-4};
        ((GridBagLayout)getLayout()).rowWeights = new double[] {0.0, 1.0, 0.0, 1.0E-4};

        //---- hostLabel ----
        hostLabel.setText("Host:");
        add(hostLabel, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(hostTextField, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        clearButton.setText("Clear");
        clearButton.addActionListener(this::clearActionPerformed);
        add(clearButton,  new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        hostComboBox.setMaximumRowCount(5);
        add(hostComboBox, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setVisible(false);
        add(splitPane, new GridBagConstraints(1, 1, 3, 3, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        setAutoMatch();
    }

    private static List<String> getHostByList() {
        return new ArrayList<>(ConfigEntry.globalDataMap.keySet());
    }

    /**
     * 设置输入自动匹配
     */
    private void setAutoMatch() {
        populateComboBoxModel();

        hostComboBox.setSelectedItem(null);
        hostComboBox.addActionListener(this::handleComboBoxAction);

        hostTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                handleKeyEvents(e);
            }
        });

        hostTextField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                filterComboBoxList();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filterComboBoxList();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                filterComboBoxList();
            }

        });
    }

    private void populateComboBoxModel() {
        for (String host : getHostByList()) {
            comboBoxModel.addElement(host);
        }
    }

    private void handleComboBoxAction(ActionEvent e) {
        if (!isMatchHost && hostComboBox.getSelectedItem() != null) {
            String selectedHost = hostComboBox.getSelectedItem().toString();
            hostTextField.setText(selectedHost);
            populateTabbedPaneByHost(selectedHost);
        }
    }
    private void handleKeyEvents(KeyEvent e) {
        isMatchHost = true;
        int keyCode = e.getKeyCode();

        if (keyCode == KeyEvent.VK_SPACE && hostComboBox.isPopupVisible()) {
            e.setKeyCode(KeyEvent.VK_ENTER);
        }

        if (Arrays.asList(KeyEvent.VK_DOWN, KeyEvent.VK_UP).contains(keyCode)) {
            hostComboBox.dispatchEvent(e);
        }

        if (keyCode == KeyEvent.VK_ENTER) {
            isMatchHost = false;
            handleComboBoxAction(null);
            hostComboBox.setPopupVisible(false);
        }

        if (keyCode == KeyEvent.VK_ESCAPE) {
            hostComboBox.setPopupVisible(false);
        }

        isMatchHost = false;
    }

    private void filterComboBoxList() {
        isMatchHost = true;
        comboBoxModel.removeAllElements();
        String input = hostTextField.getText().toLowerCase();

        if (!input.isEmpty()) {
            for (String host : getHostByList()) {
                String lowerCaseHost = host.toLowerCase();
                if (lowerCaseHost.contains(input)) {
                    if (lowerCaseHost.equals(input)) {
                        comboBoxModel.insertElementAt(lowerCaseHost, 0);
                        comboBoxModel.setSelectedItem(lowerCaseHost);
                    } else {
                        comboBoxModel.addElement(host);
                    }
                }
            }
        }

        hostComboBox.setPopupVisible(comboBoxModel.getSize() > 0);
        isMatchHost = false;
    }

    private void applyHostFilter(String filterText) {
        TableRowSorter<TableModel> sorter = (TableRowSorter<TableModel>) table.getRowSorter();

        String cleanedText = StringHelper.replaceFirstOccurrence(filterText, "*.", "");

        if (cleanedText.contains("*")) {
            cleanedText = "";
        }

        RowFilter<TableModel, Integer> filter = RowFilter.regexFilter(cleanedText, 1);
        sorter.setRowFilter(filter);

        messagePanel.applyHostFilter(filterText);
    }

    private void populateTabbedPaneByHost(String selectedHost) {
        if (!Objects.equals(selectedHost, "")) {
            ConcurrentHashMap<String, Map<String, List<String>>> dataMap = ConfigEntry.globalDataMap;
            Map<String, List<String>> selectedDataMap;

            dataTabbedPane.removeAll();
            dataTabbedPane.setPreferredSize(new Dimension(500,0));
            dataTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
            splitPane.setLeftComponent(dataTabbedPane);

            if (selectedHost.contains("*")) {
                // 通配符数据
                selectedDataMap = new HashMap<>();
                String hostPattern = StringHelper.replaceFirstOccurrence(selectedHost, "*.", "");
                for (String key : dataMap.keySet()) {
                    if (key.contains(hostPattern) || selectedHost.equals("*")) {
                        Map<String, List<String>> ruleMap = dataMap.get(key);
                        for (String ruleKey : ruleMap.keySet()) {
                            List<String> dataList = ruleMap.get(ruleKey);
                            if (selectedDataMap.containsKey(ruleKey)) {
                                List<String> mergedList = new ArrayList<>(selectedDataMap.get(ruleKey));
                                mergedList.addAll(dataList);
                                HashSet<String> uniqueSet = new HashSet<>(mergedList);
                                selectedDataMap.put(ruleKey, new ArrayList<>(uniqueSet));
                            } else {
                                selectedDataMap.put(ruleKey, dataList);
                            }
                        }
                    }
                }
            } else {
                selectedDataMap = dataMap.get(selectedHost);
            }

            if (selectedHost.equals("**")) {
                for (ConcurrentHashMap.Entry<String, Map<String, List<String>>> entry : dataMap.entrySet()) {
                    JTabbedPane newTabbedPane = new JTabbedPane();
                    newTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

                    for (Map.Entry<String, List<String>> entrySet : entry.getValue().entrySet()) {
                        currentWorker = new SwingWorker<Object, Void>() {
                            @Override
                            protected Object[] doInBackground() throws Exception {
                                String tabTitle = String.format("%s (%s)", entrySet.getKey(),
                                        entrySet.getValue().size());
                                DatatablePanel datatablePanel = new DatatablePanel(entrySet.getKey(),
                                        entrySet.getValue());
                                datatablePanel.setTableListener(messagePanel);
                                return new Object[] {tabTitle, datatablePanel};
                            }

                            @Override
                            protected void done() {
                                if (!isCancelled()) {
                                    try {
                                        Object[] result = (Object[]) get();
                                        SwingUtilities.invokeLater(() -> {
                                            newTabbedPane.addTab(result[0].toString(), (DatatablePanel) result[1]);
                                            dataTabbedPane.addTab(entry.getKey(), newTabbedPane);
                                        });
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        };
                        currentWorker.execute();
                    }
                }

                dataTabbedPane.addChangeListener(changeListenerInstance);
            } else {
                dataTabbedPane.removeChangeListener(changeListenerInstance);

                for (Map.Entry<String, List<String>> entry : selectedDataMap.entrySet()) {
                    String tabTitle = String.format("%s (%s)", entry.getKey(), entry.getValue().size());
                    DatatablePanel datatablePanel = new DatatablePanel(entry.getKey(), entry.getValue());
                    datatablePanel.setTableListener(messagePanel);
                    dataTabbedPane.addTab(tabTitle, datatablePanel);
                }
            }

            // 展示请求消息表单
            JSplitPane messageSplitPane = this.messagePanel.getPanel();
            this.splitPane.setRightComponent(messageSplitPane);
            // 获取字段
            table = this.messagePanel.getTable();

            // 设置对应字段宽度
            TableColumnModel columnModel = table.getColumnModel();
            TableColumn column = columnModel.getColumn(1);
            column.setPreferredWidth(300);
            column = columnModel.getColumn(2);
            column.setPreferredWidth(300);

            splitPane.setVisible(true);
            applyHostFilter(selectedHost);

            // 主动调用一次stateChanged，使得dataTabbedPane可以精准展示内容
            if (selectedHost.equals("**")) {
                changeListenerInstance.stateChanged(null);
            }

            hostTextField.setText(selectedHost);

        }
    }
}