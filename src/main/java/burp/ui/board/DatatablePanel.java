package burp.ui.board;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.ScrollPaneConstants;
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
    private int pageSize; // 动态计算的，每页显示多少条记录
    private int currentPage; // 当前页码
    private List<String> fullList; // 假设这是一个包含所有数据的列表
    private JScrollPane scrollPane;
    private String tableName;
    private final int SHOW_LENGTH = 3000;

    public DatatablePanel(String tableName, List<String> list) {
        fullList = list;
        currentPage = 0;
        pageSize = 10;
        this.tableName = tableName;

        String[] columnNames = {"#", "Information"};
        model = new DefaultTableModel(columnNames, 0);
        table = new JTable(model);
        sorter = new TableRowSorter<>(model);

        table.setRowSorter(sorter);
        TableColumn idColumn = table.getColumnModel().getColumn(0);
        idColumn.setMaxWidth(50);

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
        scrollPane = new JScrollPane(table);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                updatePageSize();
            }
        });

        // 添加滚动监听器，以加载更多数据
        scrollPane.getVerticalScrollBar().addAdjustmentListener(new AdjustmentListener() {
            @Override
            public void adjustmentValueChanged(AdjustmentEvent e) {
                if (fullList.size() > SHOW_LENGTH) {
                    if (!e.getValueIsAdjusting() && !scrollPane.getVerticalScrollBar().getValueIsAdjusting()) {
                        if (scrollPane.getVerticalScrollBar().getValue() == scrollPane.getVerticalScrollBar().getMaximum() - scrollPane.getVerticalScrollBar().getVisibleAmount()) {
                            if ((currentPage + 1) * pageSize < fullList.size()) {
                                currentPage++;
                                loadPageData();
                            }
                        }
                    }
                }
            }
        });

        setLayout(new BorderLayout(0, 5));
        add(scrollPane, BorderLayout.CENTER);
        add(searchField, BorderLayout.SOUTH);
        loadPageData();
    }

    // 加载指定页的数据
    private void loadPageData() {
        if (fullList.size() > SHOW_LENGTH) {
            int start = currentPage * pageSize;
            int end = Math.min((currentPage + 1) * pageSize, fullList.size());
            int lastRow = model.getRowCount();
            start = Math.max(start, lastRow);

            for (int i = start; i < end; i++) {
                addRowToTable(model, new Object[]{fullList.get(i)});
            }
        } else {
            for (String item : fullList) {
                addRowToTable(model, new Object[]{item});
            }
        }
    }

    public void updatePageSize() {
        if (fullList.size() > SHOW_LENGTH && isShowing()) {
            int oldPageSize = pageSize;
            pageSize = getDynamicSize();
            if (oldPageSize != pageSize) {
                currentPage = 0;
                loadPageData();
            }
        }
    }

    private int getDynamicSize() {
        int visibleHeight = scrollPane.getViewport().getViewRect().height;
        int rowHeight = table.getRowHeight();
        return Math.max(1, visibleHeight / rowHeight + 2);
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
                        String rowData = table.getValueAt(selectedRow, 0).toString();
                        messagePanel.applyMessageFilter(tableName, rowData);
                    }
                }
            }
        });
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

    public JTable getTable() {
        return this.table;
    }
}
