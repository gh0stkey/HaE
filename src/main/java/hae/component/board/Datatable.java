package hae.component.board;

import burp.api.montoya.MontoyaApi;
import hae.component.board.message.MessageTableModel;
import hae.utils.ui.UIEnhancer;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;

public class Datatable extends JPanel {
    private final MontoyaApi api;
    private final JTable dataTable;
    private final DefaultTableModel dataTableModel;
    private final JTextField searchField;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final JCheckBox searchMode = new JCheckBox("Reverse search");
    private final String tabName;

    public Datatable(MontoyaApi api, String tabName, List<String> dataList) {
        this.api = api;
        this.tabName = tabName;

        String[] columnNames = {"#", "Information"};

        dataTableModel = new DefaultTableModel(columnNames, 0);
        dataTable = new JTable(dataTableModel);
        sorter = new TableRowSorter<>(dataTableModel);

        searchField = new JTextField();

        initComponents(dataList);
    }

    private void initComponents(List<String> dataList) {
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

        // 设置灰色默认文本
        String searchText = "Search";
        UIEnhancer.setTextFieldPlaceholder(searchField, searchText);

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

        });

        // 设置布局
        JScrollPane scrollPane = new JScrollPane(dataTable);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);

        searchMode.addItemListener(e -> performSearch());

        setLayout(new BorderLayout(0, 5));

        JPanel optionsPanel = new JPanel();
        optionsPanel.setBorder(BorderFactory.createEmptyBorder(2, 3, 5, 5));
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.X_AXIS));

        // 新增复选框要在这修改rows
        JPanel menuPanel = new JPanel(new GridLayout(1, 1));
        menuPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JPopupMenu menu = new JPopupMenu();
        menuPanel.add(searchMode);
        menu.add(menuPanel);

        JButton settingsButton = new JButton("Settings");
        settingsButton.addActionListener(e -> {
            int x = settingsButton.getX();
            int y = settingsButton.getY() - menu.getPreferredSize().height;
            menu.show(settingsButton, x, y);
        });

        optionsPanel.add(settingsButton);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(searchField);

        add(scrollPane, BorderLayout.CENTER);
        add(optionsPanel, BorderLayout.SOUTH);
    }

    private void addRowToTable(Object[] data) {
        int rowCount = dataTableModel.getRowCount();
        int id = rowCount > 0 ? (Integer) dataTableModel.getValueAt(rowCount - 1, 0) + 1 : 1;
        Object[] rowData = new Object[data.length + 1];
        rowData[0] = id;
        System.arraycopy(data, 0, rowData, 1, data.length);
        dataTableModel.addRow(rowData);
    }

    private void performSearch() {
        if (searchField.getForeground().equals(Color.BLACK)) {
            RowFilter<Object, Object> rowFilter = new RowFilter<Object, Object>() {
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
            sorter.setRowFilter(rowFilter);
        }
    }

    public void setTableListener(MessageTableModel messagePanel) {
        // 表格复制功能
        dataTable.setTransferHandler(new TransferHandler() {
            @Override
            public void exportToClipboard(JComponent comp, Clipboard clip, int action) throws IllegalStateException {
                if (comp instanceof JTable) {
                    StringSelection stringSelection = new StringSelection(getSelectedDataAtTable((JTable) comp));
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

    public String getSelectedDataAtTable(JTable table) {
        int[] selectRows = table.getSelectedRows();
        StringBuilder selectData = new StringBuilder();

        for (int row : selectRows) {
            selectData.append(table.getValueAt(row, 1).toString()).append("\n");
        }

        // 便于单行复制，去除最后一个换行符
        if (!selectData.isEmpty()) {
            selectData.deleteCharAt(selectData.length() - 1);
            return selectData.toString();
        } else {
            return "";
        }
    }

    public JTable getDataTable() {
        return this.dataTable;
    }
}

