package burp.ui.board;

import burp.config.ConfigEntry;
import burp.core.utils.StringHelper;
import burp.ui.board.MessagePanel.Table;

import java.util.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * @author LinChen && EvilChen
 */

public class Databoard extends JPanel {
    private static Boolean isMatchHost = false;
    private JLabel hostLabel;
    private JTextField hostTextField;
    private JTabbedPane dataTabbedPaneA;
    private JTabbedPane dataTabbedPaneB;
    private JButton clearButton;
    private JSplitPane splitPane;
    private MessagePanel messagePanel;
    private Table table;
    DefaultComboBoxModel comboBoxModel = new DefaultComboBoxModel();
    JComboBox hostComboBox = new JComboBox(comboBoxModel);

    public Databoard(MessagePanel messagePanel) {
        this.messagePanel = messagePanel;
        initComponents();
    }

    private void cleanUI() {
        dataTabbedPaneA.removeAll();
        dataTabbedPaneB.removeAll();
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
                ConfigEntry.globalDataMap.keySet().removeIf(i -> i.contains(cleanedHost) || cleanedHost.equals("**"));
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
        dataTabbedPaneA = new JTabbedPane(JTabbedPane.TOP);
        dataTabbedPaneB = new JTabbedPane(JTabbedPane.TOP);
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

        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setVisible(false);

        add(splitPane, new GridBagConstraints(1, 1, 3, 2, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        hostTextField.setLayout(new BorderLayout());
        hostTextField.add(hostComboBox, BorderLayout.SOUTH);
        hostComboBox.setMaximumRowCount(5);
        hostComboBox.setPreferredSize(new Dimension(super.getPreferredSize().width, 0));

        // 由于主题切换造成的UI组件重绘，而自定义组件没有正确地与之同步，因此需要事件监听来进行同步
        UIManager.addPropertyChangeListener(evt -> {
            if ("lookAndFeel".equals(evt.getPropertyName())) {
                SwingUtilities.invokeLater(() -> {
                    hostTextField.remove(hostComboBox);
                    hostTextField.add(hostComboBox, BorderLayout.SOUTH);
                    hostTextField.revalidate();
                    hostTextField.repaint();
                });
            }
        });

        setAutoMatch();
    }

    private static List<String> getHostByList() {
        return new ArrayList<>(ConfigEntry.globalDataMap.keySet());
    }

    /**
     * 设置输入自动匹配
     */
    private void setAutoMatch() {
        isMatchHost = false;

        for (String host : getHostByList()) {
            comboBoxModel.addElement(host);
        }

        hostComboBox.setSelectedItem(null);

        hostComboBox.addActionListener(e -> {
            if (!isMatchHost) {
                if (hostComboBox.getSelectedItem() != null) {
                    String selectedHost = hostComboBox.getSelectedItem().toString();
                    hostTextField.setText(selectedHost);
                    populateTabbedPaneByHost(selectedHost);
                }
            }
        });

        // 事件监听
        hostTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                isMatchHost = true;
                int keyCode = e.getKeyCode();

                if (keyCode == KeyEvent.VK_SPACE && hostComboBox.isPopupVisible()) {
                    e.setKeyCode(KeyEvent.VK_ENTER);
                }

                if (keyCode == KeyEvent.VK_ENTER || keyCode == KeyEvent.VK_UP || keyCode == KeyEvent.VK_DOWN) {
                    e.setSource(hostComboBox);
                    hostComboBox.dispatchEvent(e);

                    if (keyCode == KeyEvent.VK_ENTER) {
                        String selectedItem = hostComboBox.getSelectedItem().toString();
                        hostTextField.setText(selectedItem);
                        populateTabbedPaneByHost(selectedItem);
                        hostComboBox.setPopupVisible(false);
                        return;
                    }
                }

                if (keyCode == KeyEvent.VK_ESCAPE) {
                    hostComboBox.setPopupVisible(false);
                }

                isMatchHost = false;
            }
        });

        hostTextField.getDocument().addDocumentListener(new DocumentListener() {
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
                String input = hostTextField.getText().toLowerCase();
                if (!input.isEmpty()){
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
        });
    }

    private void applyHostFilter(String filterText) {
        TableRowSorter<TableModel> sorter = (TableRowSorter<TableModel>) table.getRowSorter();
        if (filterText.contains("*.")) {
            filterText = StringHelper.replaceFirstOccurrence(filterText, "*.", "");
        } else if (filterText.contains("*")) {
            filterText = "";
        }
        RowFilter<TableModel, Integer> filter = RowFilter.regexFilter(filterText, 1);
        sorter.setRowFilter(filter);
        filterText = filterText.isEmpty() ? "*" : filterText;

        messagePanel.applyHostFilter(filterText);
    }

    private void populateTabbedPaneByHost(String selectedHost) {
        if (!Objects.equals(selectedHost, "")) {
            Map<String, Map<String, List<String>>> dataMap = ConfigEntry.globalDataMap;
            Map<String, List<String>> selectedDataMap;

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

            // 由于removeChangeListener不知什么原因不生效，因此建立两个tabbedPane
            dataTabbedPaneA.removeAll();
            dataTabbedPaneB.removeAll();

            ChangeListener changeListenerInstance = new ChangeListener() {
                @Override
                public void stateChanged(ChangeEvent e) {
                    int selectedIndex = dataTabbedPaneA.getSelectedIndex();
                    String selectedTitle = "";
                    if (selectedIndex != -1) {
                        selectedTitle = dataTabbedPaneA.getTitleAt(selectedIndex);
                    }
                    applyHostFilter(selectedTitle);
                }
            };

            if (selectedHost.equals("**")) {
                dataTabbedPaneA.setPreferredSize(new Dimension(500,0));
                dataTabbedPaneA.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                splitPane.setLeftComponent(dataTabbedPaneA);
                for (Map.Entry<String, Map<String, List<String>>> entry : dataMap.entrySet()) {
                    JTabbedPane newTabbedPane = new JTabbedPane();
                    newTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                    for (Map.Entry<String, List<String>> entrySet : entry.getValue().entrySet()) {
                        Thread t = new Thread(() -> {
                            String tabTitle = String.format("%s (%s)", entrySet.getKey(), entrySet.getValue().size());
                            newTabbedPane.addTab(tabTitle, new DataTable(entrySet.getKey(), entrySet.getValue()));
                            dataTabbedPaneA.addTab(entry.getKey(), newTabbedPane);
                        });
                        t.start();
                        try {
                            t.join();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
                dataTabbedPaneA.addChangeListener(changeListenerInstance);
            } else {
                dataTabbedPaneB.setPreferredSize(new Dimension(500,0));
                dataTabbedPaneB.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                splitPane.setLeftComponent(dataTabbedPaneB);
                for (Map.Entry<String, List<String>> entry : selectedDataMap.entrySet()) {
                    String tabTitle = String.format("%s (%s)", entry.getKey(), entry.getValue().size());
                    dataTabbedPaneB.addTab(tabTitle, new DataTable(entry.getKey(), entry.getValue()));
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

    class DataTable extends JPanel {
        private final JTable table;
        private final DefaultTableModel model;
        private final JTextField searchField;
        private TableRowSorter<DefaultTableModel> sorter;


        public DataTable(String tableName, List<String> list) {
            model = new DefaultTableModel();
            table = new JTable(model);
            sorter = new TableRowSorter<>(model);

            table.setRowSorter(sorter);
            table.setDefaultEditor(Object.class, null);

            // 表格内容双击事件
            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        int selectedRow = table.getSelectedRow();
                        if (selectedRow != -1) {
                            String rowData = table.getValueAt(selectedRow, 0).toString();
                            messagePanel.applyMessageFilter(tableName, rowData);
                        }
                    }
                }
            });

            model.addColumn("Information");
            for (String item : list) {
                model.addRow(new Object[]{item});
            }

            String defaultText = "Search";

            searchField = new JTextField(defaultText);
            // 设置灰色默认文本Search
            searchField.setForeground(Color.GRAY);
            searchField.addFocusListener(new FocusListener() {
                @Override
                public void focusGained(FocusEvent e) {
                    if (searchField.getText().equals(defaultText)) {
                        searchField.setText("");
                        searchField.setForeground(Color.BLACK);
                    }
                }

                @Override
                public void focusLost(FocusEvent e) {
                    if (searchField.getText().isEmpty()) {
                        searchField.setForeground(Color.GRAY);
                        searchField.setText(defaultText);
                    }
                }
            });

            // 监听输入框内容输入、更新、删除
            searchField.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    performSearch();
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    performSearch();
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    performSearch();
                }

                private void performSearch() {
                    // 通过字体颜色来判断是否可以进行过滤
                    if (searchField.getForeground() == Color.BLACK) {
                        String searchText = searchField.getText();
                        if (sorter == null) {
                            sorter = new TableRowSorter<>(model);
                            table.setRowSorter(sorter);
                        }
                        RowFilter<DefaultTableModel, Object> rowFilter = RowFilter.regexFilter(String.format("%s%s", "(?i)", searchText), 0);
                        sorter.setRowFilter(rowFilter);
                    }
                }
            });

            // 设置布局
            JScrollPane scrollPane = new JScrollPane(table);

            setLayout(new BorderLayout(0, 5));
            add(scrollPane, BorderLayout.CENTER);
            add(searchField, BorderLayout.SOUTH);
        }
    }
}
