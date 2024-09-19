package hae.component.board.table;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import hae.component.board.Databoard;
import hae.component.board.message.MessageTableModel;
import hae.utils.ConfigLoader;
import hae.utils.UIEnhancer;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class Datatable extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final JTable dataTable;
    private final DefaultTableModel dataTableModel;
    private final JTextField searchField;
    private final JTextField secondSearchField;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final JCheckBox searchMode = new JCheckBox("Reverse search");
    private final String tabName;
    private final JProgressBar progressBar;
    private final JPopupMenu aiEmpoweredMenu;
    private final JPanel footerPanel;

    public Datatable(MontoyaApi api, ConfigLoader configLoader, String tabName, List<String> dataList) {
        this.api = api;
        this.configLoader = configLoader;
        this.tabName = tabName;
        this.progressBar = new JProgressBar();

        String[] columnNames = {"#", "Information"};
        this.dataTableModel = new DefaultTableModel(columnNames, 0);

        this.dataTable = new JTable(dataTableModel);
        this.sorter = new TableRowSorter<>(dataTableModel);
        this.searchField = new JTextField(10);
        this.secondSearchField = new JTextField(10);
        this.aiEmpoweredMenu = new JPopupMenu();
        this.footerPanel = new JPanel(new BorderLayout(0, 5));

        initComponents(dataList);
    }

    private void initComponents(List<String> dataList) {
        progressBar.setVisible(false);

        // 设置ID排序
        sorter.setComparator(0, new Comparator<Integer>() {
            @Override
            public int compare(Integer s1, Integer s2) {
                return s1.compareTo(s2);
            }
        });

        dataTable.setRowSorter(sorter);
        TableColumn idColumn = dataTable.getColumnModel().getColumn(0);
        idColumn.setMaxWidth(50);

        for (String item : dataList) {
            if (!item.isEmpty()) {
                addRowToTable(new Object[]{item});
            }
        }

        UIEnhancer.setTextFieldPlaceholder(searchField, "Search");
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

        });

        UIEnhancer.setTextFieldPlaceholder(secondSearchField, "Second search");
        secondSearchField.getDocument().addDocumentListener(new DocumentListener() {
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

        });

        // 设置布局
        JScrollPane scrollPane = new JScrollPane(dataTable);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);

        setLayout(new BorderLayout(0, 5));

        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.X_AXIS));

        // Settings按钮
        JPanel settingMenuPanel = new JPanel(new GridLayout(1, 1));
        settingMenuPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JPopupMenu settingMenu = new JPopupMenu();
        settingMenuPanel.add(searchMode);
        searchMode.addItemListener(e -> performSearch());
        settingMenu.add(settingMenuPanel);

        JButton settingsButton = new JButton("Settings");
        setMenuShow(settingMenu, settingsButton);

        // AI Empowered按钮
        JPanel aiEmpoweredPanel = new JPanel(new GridLayout(2, 1));
        aiEmpoweredPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JButton empoweredByAlibabaButton = new JButton("Alibaba - QwenLong");
        empoweredByAlibabaButton.addActionListener(e -> {
            aiEmpoweredByAlibabaActionPerformed(e, tabName, getTableData(dataTable));
        });
        JButton empoweredByMoonshotButton = new JButton("Moonshot - Kimi");
        empoweredByMoonshotButton.addActionListener(e -> {
            aiEmpoweredByMoonshotActionPerformed(e, tabName, getTableData(dataTable));
        });
        aiEmpoweredPanel.add(empoweredByAlibabaButton);
        aiEmpoweredPanel.add(empoweredByMoonshotButton);
        aiEmpoweredMenu.add(aiEmpoweredPanel);

        JButton aiEmpoweredButton = new JButton("AI Empowered");
        setMenuShow(aiEmpoweredMenu, aiEmpoweredButton);
        aiEmpoweredMenu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                empoweredByAlibabaButton.setEnabled(!configLoader.getAlibabaAIAPIKey().isEmpty());
                empoweredByMoonshotButton.setEnabled(!configLoader.getMoonshotAIAPIKey().isEmpty());
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {

            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {

            }
        });

        optionsPanel.add(settingsButton);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(searchField);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(secondSearchField);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(aiEmpoweredButton);

        footerPanel.setBorder(BorderFactory.createEmptyBorder(2, 3, 5, 3));
        footerPanel.add(optionsPanel, BorderLayout.CENTER);
        footerPanel.add(progressBar, BorderLayout.SOUTH);

        add(scrollPane, BorderLayout.CENTER);
        add(footerPanel, BorderLayout.SOUTH);

        setProgressBar(false);
    }

    private void setMenuShow(JPopupMenu menu, JButton button) {
        button.addActionListener(e -> {
            Point buttonLocation = button.getLocationOnScreen();
            Dimension menuSize = menu.getPreferredSize();
            int x = buttonLocation.x + (button.getWidth() - menuSize.width) / 2;
            int y = buttonLocation.y - menuSize.height;
            menu.show(button, x - buttonLocation.x, y - buttonLocation.y);
        });
    }

    private void setProgressBar(boolean status) {
        Databoard.setProgressBar(status, progressBar, "AI+ ...");
    }

    private void addRowToTable(Object[] data) {
        int rowCount = dataTableModel.getRowCount();
        int id = rowCount > 0 ? (Integer) dataTableModel.getValueAt(rowCount - 1, 0) + 1 : 1;
        Object[] rowData = new Object[data.length + 1];
        rowData[0] = id;
        System.arraycopy(data, 0, rowData, 1, data.length);
        dataTableModel.addRow(rowData);
    }

    private void aiEmpoweredByAlibabaActionPerformed(ActionEvent e, String ruleName, String data) {
        AIPower aiPower = new AIPower(api, configLoader, "qwen-long", "https://dashscope.aliyuncs.com/compatible-mode/v1", configLoader.getAlibabaAIAPIKey().split("\\|"));
        aiEmpoweredButtonAction(ruleName, data, aiPower);
    }

    private void aiEmpoweredByMoonshotActionPerformed(ActionEvent e, String ruleName, String data) {
        AIPower aiPower = new AIPower(api, configLoader, "moonshot-v1-128k", "https://api.moonshot.cn/v1", configLoader.getMoonshotAIAPIKey().split("\\|"));
        aiEmpoweredButtonAction(ruleName, data, aiPower);
    }

    private void aiEmpoweredButtonAction(String ruleName, String data, AIPower aiPower) {
        progressBar.setVisible(true);
        aiEmpoweredMenu.setVisible(true);
        setProgressBar(true);

        SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return aiPower.chatWithAPI(ruleName, data);
            }

            @Override
            protected void done() {
                setProgressBar(false);

                try {
                    String chatReturn = get();
                    if (!chatReturn.isEmpty()) {
                        Gson gson = new Gson();
                        Type type = new TypeToken<Map<String, Object>>() {
                        }.getType();
                        Map<String, List<String>> map = gson.fromJson(chatReturn, type);

                        dataTableModel.setRowCount(0);
                        for (String item : map.get("data")) {
                            if (!item.isEmpty()) {
                                addRowToTable(new Object[]{item});
                            }
                        }

                        JOptionPane.showMessageDialog(Datatable.this, "AI+ has completed the AI empowered work.", "AI+ Info", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(Datatable.this, "AI+ returns null, please check!", "AI+ Info", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (Exception ignored) {
                    JOptionPane.showMessageDialog(Datatable.this, "AI+ returns error, please check!", "AI+ Info", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();

        aiEmpoweredMenu.setVisible(false);
    }

    private void performSearch() {
        RowFilter<Object, Object> firstRowFilter = applyFirstSearchFilter();
        RowFilter<Object, Object> secondRowFilter = applySecondFilter();
        if (searchField.getForeground().equals(Color.BLACK)) {
            sorter.setRowFilter(firstRowFilter);
            if (secondSearchField.getForeground().equals(Color.BLACK)) {
                List<RowFilter<Object, Object>> filters = new ArrayList<>();
                filters.add(firstRowFilter);
                filters.add(secondRowFilter);
                sorter.setRowFilter(RowFilter.andFilter(filters));
            }
        }
    }

    private RowFilter<Object, Object> applyFirstSearchFilter() {
        return new RowFilter<Object, Object>() {
            public boolean include(Entry<?, ?> entry) {
                String searchFieldTextText = searchField.getText();
                Pattern pattern = null;
                try {
                    pattern = Pattern.compile(searchFieldTextText, Pattern.CASE_INSENSITIVE);
                } catch (Exception ignored) {
                }

                String entryValue = ((String) entry.getValue(1)).toLowerCase();
                searchFieldTextText = searchFieldTextText.toLowerCase();
                if (pattern != null) {
                    return searchFieldTextText.isEmpty() || pattern.matcher(entryValue).find() != searchMode.isSelected();
                } else {
                    return searchFieldTextText.isEmpty() || entryValue.contains(searchFieldTextText) != searchMode.isSelected();
                }
            }
        };
    }

    private RowFilter<Object, Object> applySecondFilter() {
        return new RowFilter<Object, Object>() {
            public boolean include(Entry<?, ?> entry) {
                String searchFieldTextText = secondSearchField.getText();
                Pattern pattern = null;
                try {
                    pattern = Pattern.compile(searchFieldTextText, Pattern.CASE_INSENSITIVE);
                } catch (Exception ignored) {
                }

                String entryValue = ((String) entry.getValue(1)).toLowerCase();
                searchFieldTextText = searchFieldTextText.toLowerCase();
                if (pattern != null) {
                    return searchFieldTextText.isEmpty() || pattern.matcher(entryValue).find();
                } else {
                    return searchFieldTextText.isEmpty() || entryValue.contains(searchFieldTextText);
                }
            }
        };
    }

    public void setTableListener(MessageTableModel messagePanel) {
        // 表格复制功能
        dataTable.setTransferHandler(new TransferHandler() {
            @Override
            public void exportToClipboard(JComponent comp, Clipboard clip, int action) throws IllegalStateException {
                if (comp instanceof JTable) {
                    StringSelection stringSelection = new StringSelection(getSelectedDataAtTable((JTable) comp).replace("\0", "").replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", ""));
                    clip.setContents(stringSelection, null);
                } else {
                    super.exportToClipboard(comp, clip, action);
                }
            }
        });

        dataTable.setDefaultEditor(Object.class, null);

        // 表格内容双击事件
        dataTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int selectedRow = dataTable.getSelectedRow();
                    if (selectedRow != -1) {
                        String rowData = dataTable.getValueAt(selectedRow, 1).toString();
                        messagePanel.applyMessageFilter(tabName, rowData);
                    }
                }
            }
        });
    }

    private String getTableData(JTable table) {
        StringBuilder selectData = new StringBuilder();
        int rowCount = table.getRowCount();
        for (int i = 0; i < rowCount; i++) {
            selectData.append(table.getValueAt(i, 1).toString()).append("\r\n");
        }

        if (!selectData.isEmpty()) {
            selectData.delete(selectData.length() - 2, selectData.length());
        } else {
            return "";
        }

        return selectData.toString();
    }

    public String getSelectedDataAtTable(JTable table) {
        int[] selectRows = table.getSelectedRows();
        StringBuilder selectData = new StringBuilder();

        for (int row : selectRows) {
            selectData.append(table.getValueAt(row, 1).toString()).append("\r\n");
        }

        if (!selectData.isEmpty()) {
            selectData.delete(selectData.length() - 2, selectData.length());
        } else {
            return "";
        }

        return selectData.toString();
    }


    public JTable getDataTable() {
        return this.dataTable;
    }
}

