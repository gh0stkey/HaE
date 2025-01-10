package hae.component.board.table;

import burp.api.montoya.MontoyaApi;
import hae.component.board.message.MessageTableModel;
import hae.utils.ConfigLoader;
import hae.utils.UIEnhancer;

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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
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
    private final JPanel footerPanel;

    public Datatable(MontoyaApi api, ConfigLoader configLoader, String tabName, List<String> dataList) {
        this.api = api;
        this.configLoader = configLoader;
        this.tabName = tabName;

        String[] columnNames = {"#", "Information"};
        this.dataTableModel = new DefaultTableModel(columnNames, 0);

        this.dataTable = new JTable(dataTableModel);
        this.sorter = new TableRowSorter<>(dataTableModel);
        this.searchField = new JTextField(10);
        this.secondSearchField = new JTextField(10);
        this.footerPanel = new JPanel(new BorderLayout(0, 5));

        initComponents(dataList);
    }

    private void initComponents(List<String> dataList) {
        dataTable.setRowSorter(sorter);
        
        // 设置ID排序
        sorter.setComparator(0, new Comparator<Integer>() {
            @Override
            public int compare(Integer s1, Integer s2) {
                return s1.compareTo(s2);
            }
        });

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

        TableColumn idColumn = dataTable.getColumnModel().getColumn(0);
        idColumn.setPreferredWidth(50);
        idColumn.setMaxWidth(100);

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

        optionsPanel.add(settingsButton);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(searchField);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(secondSearchField);

        footerPanel.setBorder(BorderFactory.createEmptyBorder(2, 3, 5, 3));
        footerPanel.add(optionsPanel, BorderLayout.CENTER);

        add(scrollPane, BorderLayout.CENTER);
        add(footerPanel, BorderLayout.SOUTH);
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


    private void addRowToTable(Object[] data) {
        int rowCount = dataTableModel.getRowCount();
        int id = rowCount > 0 ? (Integer) dataTableModel.getValueAt(rowCount - 1, 0) + 1 : 1;
        Object[] rowData = new Object[data.length + 1];
        rowData[0] = id;
        System.arraycopy(data, 0, rowData, 1, data.length);
        dataTableModel.addRow(rowData);
    }

    private void performSearch() {
        RowFilter<Object, Object> firstRowFilter = getObjectObjectRowFilter(searchField);
        RowFilter<Object, Object> secondRowFilter = getObjectObjectRowFilter(secondSearchField);
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

    private RowFilter<Object, Object> getObjectObjectRowFilter(JTextField searchField) {
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
                boolean filterReturn = searchFieldTextText.isEmpty();
                if (pattern != null) {
                    filterReturn = filterReturn || pattern.matcher(entryValue).find() != searchMode.isSelected();
                }

                return filterReturn || entryValue.contains(searchFieldTextText) != searchMode.isSelected();
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

