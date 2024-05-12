package hae.component.board;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import hae.component.board.message.MessageTableModel;
import hae.component.board.message.MessageTableModel.MessageTable;
import hae.utils.config.ConfigLoader;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Databoard extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final MessageTableModel messageTableModel;
    private JTextField hostTextField;
    private JTabbedPane dataTabbedPane;
    private JSplitPane splitPane;
    private MessageTable messageTable;

    private static Boolean isMatchHost = false;
    private final DefaultComboBoxModel comboBoxModel = new DefaultComboBoxModel();
    private final JComboBox hostComboBox = new JComboBox(comboBoxModel);

    public Databoard(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel) {
        this.api = api;
        this.configLoader = configLoader;
        this.messageTableModel = messageTableModel;

        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        ((GridBagLayout) getLayout()).columnWidths = new int[]{25, 0, 0, 0, 20, 0};
        ((GridBagLayout) getLayout()).rowHeights = new int[]{0, 65, 20, 0};
        ((GridBagLayout) getLayout()).columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, 0.0, 1.0E-4};
        ((GridBagLayout) getLayout()).rowWeights = new double[]{0.0, 1.0, 0.0, 1.0E-4};

        JLabel hostLabel = new JLabel("Host:");

        JButton clearButton = new JButton("Clear");
        JButton actionButton = new JButton("Action");
        JPanel menuPanel = new JPanel(new GridLayout(1, 1));
        menuPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JPopupMenu menu = new JPopupMenu();
        menuPanel.add(clearButton);
        menu.add(menuPanel);

        hostTextField = new JTextField();
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        actionButton.addActionListener(e -> {
            int x = 0;
            int y = actionButton.getHeight();
            menu.show(actionButton, x, y);
        });

        clearButton.addActionListener(this::clearActionPerformed);

        splitPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                resizePanel();
            }
        });

        splitPane.setVisible(false);

        add(hostLabel, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(hostTextField, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(actionButton, new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(splitPane, new GridBagConstraints(1, 1, 3, 3, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        hostComboBox.setMaximumRowCount(5);
        add(hostComboBox, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        setAutoMatch();
    }

    private void resizePanel() {
        splitPane.setDividerLocation(0.4);
        TableColumnModel columnModel = messageTable.getColumnModel();
        int totalWidth = (int) (getWidth() * 0.6);
        columnModel.getColumn(0).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(1).setPreferredWidth((int) (totalWidth * 0.3));
        columnModel.getColumn(2).setPreferredWidth((int) (totalWidth * 0.3));
        columnModel.getColumn(3).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(4).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(5).setPreferredWidth((int) (totalWidth * 0.1));
    }

    private void setAutoMatch() {
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

    private void populateTabbedPaneByHost(String selectedHost) {
        if (!Objects.equals(selectedHost, "")) {
            ConcurrentHashMap<String, Map<String, List<String>>> dataMap = Config.globalDataMap;
            Map<String, List<String>> selectedDataMap;

            dataTabbedPane.removeAll();
            dataTabbedPane.setPreferredSize(new Dimension(500, 0));
            dataTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
            splitPane.setLeftComponent(dataTabbedPane);

            if (selectedHost.contains("*")) {
                // 通配符数据
                selectedDataMap = new HashMap<>();
                String hostPattern = StringProcessor.replaceFirstOccurrence(selectedHost, "*.", "");
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

            for (Map.Entry<String, List<String>> entry : selectedDataMap.entrySet()) {
                String tabTitle = String.format("%s (%s)", entry.getKey(), entry.getValue().size());
                Datatable datatablePanel = new Datatable(api, entry.getKey(), entry.getValue());
                datatablePanel.setTableListener(messageTableModel);
                dataTabbedPane.addTab(tabTitle, datatablePanel);
            }

            // 展示请求消息表单
            JSplitPane messageSplitPane = messageTableModel.getSplitPane();
            this.splitPane.setRightComponent(messageSplitPane);
            messageTable = messageTableModel.getMessageTable();

            resizePanel();
            splitPane.setVisible(true);

            applyHostFilter(selectedHost);
            hostTextField.setText(selectedHost);
        }
    }

    private void applyHostFilter(String filterText) {
        TableRowSorter<TableModel> sorter = (TableRowSorter<TableModel>) messageTable.getRowSorter();

        String cleanedText = StringProcessor.replaceFirstOccurrence(filterText, "*.", "");

        if (cleanedText.contains("*")) {
            cleanedText = "";
        }

        RowFilter<TableModel, Integer> filter = RowFilter.regexFilter(cleanedText, 1);
        sorter.setRowFilter(filter);

        messageTableModel.applyHostFilter(filterText);
    }

    private List<String> getHostByList() {
        return new ArrayList<>(Config.globalDataMap.keySet());
    }

    private void clearActionPerformed(ActionEvent e) {
        int retCode = JOptionPane.showConfirmDialog(null, "Do you want to clear data?", "Info",
                JOptionPane.YES_NO_OPTION);
        String host = hostTextField.getText();
        if (retCode == JOptionPane.YES_OPTION && !host.isEmpty()) {
            dataTabbedPane.removeAll();
            splitPane.setVisible(false);

            String cleanedHost = StringProcessor.replaceFirstOccurrence(host, "*.", "");

            if (host.contains("*")) {
                Config.globalDataMap.keySet().removeIf(i -> i.contains(cleanedHost) || cleanedHost.contains("*"));
            } else {
                Config.globalDataMap.remove(host);
            }

            messageTableModel.deleteByHost(cleanedHost);
        }
    }
}
