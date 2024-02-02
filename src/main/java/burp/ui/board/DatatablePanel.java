package burp.ui.board;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import jregex.Pattern;
import jregex.REFlags;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.ScrollPaneConstants;
import javax.swing.TransferHandler;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

public class DatatablePanel extends JPanel {
    private final JTable table;
    private final DefaultTableModel model;
    private final JTextField searchField;
    private TableRowSorter<DefaultTableModel> sorter;
    private JScrollPane scrollPane;
    private String tableName;
    private JCheckBox searchMode = new JCheckBox("Reverse search");

    public DatatablePanel(String tableName, List<String> list) {
        this.tableName = tableName;

        String[] columnNames = {"#", "Information"};
        model = new DefaultTableModel(columnNames, 0);
        table = new JTable(model);
        sorter = new TableRowSorter<>(model);
        // 设置ID排序
        sorter.setComparator(0, new Comparator<Integer>() {
            @Override
            public int compare(Integer s1, Integer s2) {
                return s1.compareTo(s2);
            }
        });

        table.setRowSorter(sorter);
        TableColumn idColumn = table.getColumnModel().getColumn(0);
        idColumn.setMaxWidth(50);

        for (String item : list) {
            if (!item.isEmpty()) {
                addRowToTable(model, new Object[]{item});
            }
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

        });

        // 设置布局
        scrollPane = new JScrollPane(table);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);

        searchMode.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                performSearch();
            }
        });

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
        settingsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int x = settingsButton.getX();
                int y = settingsButton.getY() - menu.getPreferredSize().height;
                menu.show(settingsButton, x, y);
            }
        });

        optionsPanel.add(settingsButton);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(searchField);

        add(scrollPane, BorderLayout.CENTER);
        add(optionsPanel, BorderLayout.SOUTH);
    }

    private static void addRowToTable(DefaultTableModel model, Object[] data) {
        // 获取当前ID
        int rowCount = model.getRowCount();
        int id = rowCount > 0 ? (Integer) model.getValueAt(rowCount - 1, 0) + 1 : 1;
        Object[] rowData = new Object[data.length + 1];
        rowData[0] = id; // 设置ID列的值
        System.arraycopy(data, 0, rowData, 1, data.length); // 拷贝其余数据
        model.addRow(rowData); // 添加行
    }

    private void performSearch() {
        if (searchField.getForeground().equals(Color.BLACK)) {
            RowFilter<Object, Object> rowFilter = new RowFilter<Object, Object>() {
                public boolean include(Entry<?, ?> entry) {
                    String searchFieldTextText = searchField.getText();
                    Pattern pattern = null;
                    try {
                        pattern = new Pattern(searchFieldTextText, REFlags.IGNORE_CASE);
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

    public void setTableListener(MessagePanel messagePanel) {
        table.setDefaultEditor(Object.class, null);

        // 表格内容双击事件
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        String rowData = table.getValueAt(selectedRow, 1).toString();
                        messagePanel.applyMessageFilter(tableName, rowData);
                    }
                }
            }
        });

        table.setTransferHandler(new TransferHandler() {
            @Override
            public void exportToClipboard(JComponent comp, Clipboard clip, int action) throws IllegalStateException {
                if (comp instanceof JTable) {
                    StringSelection stringSelection = new StringSelection(getSelectedData(
                            (JTable) comp));
                    clip.setContents(stringSelection, null);
                } else {
                    super.exportToClipboard(comp, clip, action);
                }
            }
        });
    }

    public String getSelectedData(JTable table) {
        int[] selectRows = table.getSelectedRows();
        StringBuilder selectData = new StringBuilder();
        for (int row : selectRows) {
            selectData.append(table.getValueAt(row, 1).toString()).append("\n");
        }

        // 便于单行复制，去除最后一个换行符
        if (selectData.length() > 0){
            selectData.deleteCharAt(selectData.length() - 1);
        }

        return selectData.toString();
    }

    public JTable getTable() {
        return this.table;
    }
}