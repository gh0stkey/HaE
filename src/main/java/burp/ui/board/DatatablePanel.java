package burp.ui.board;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Pattern;
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
    private int pageSize; // 动态计算的，每页显示多少条记录
    private int currentPage; // 当前页码
    private List<String> fullList; // 假设这是一个包含所有数据的列表
    private JScrollPane scrollPane;
    private String tableName;
    private final int SHOW_LENGTH = 2;
    private JCheckBox searchMode = new JCheckBox("Reverse search");
    private JCheckBox showMode = new JCheckBox("Show all data");
    private boolean scrollFlag = true;

    public DatatablePanel(String tableName, List<String> list) {
        fullList = list;
        currentPage = 0;
        pageSize = 10;
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
        scrollPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                updatePageSize();
            }
        });

        // 添加滚动监听器，以加载更多数据
        AdjustmentListener scrollListener = new AdjustmentListener() {
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
        };

        scrollPane.getVerticalScrollBar().addAdjustmentListener(scrollListener);

        searchMode.addItemListener(new ItemListener() {
            public void itemStateChanged(ItemEvent e) {
                performSearch();
            }
        });

        showMode.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                model.setRowCount(0);
                if (e.getStateChange() == ItemEvent.SELECTED) {
                    scrollFlag = false;
                    loadPageData();
                    showMode.setEnabled(false);
                }
            }
        });

        setLayout(new BorderLayout(0, 5));

        JPanel optionsPanel = new JPanel();
        optionsPanel.setBorder(BorderFactory.createEmptyBorder(2, 3, 5, 5));
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.X_AXIS));

        // 新增复选框要在这修改rows
        JPanel menuPanel = new JPanel(new GridLayout(2, 1));
        menuPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JPopupMenu menu = new JPopupMenu();
        menuPanel.add(searchMode);
        menuPanel.add(showMode);
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

        loadPageData();
    }

    private void performSearch() {
        // 检查文本字段的字体颜色是否为黑色，表示可以进行搜索
        if (searchField.getForeground().equals(Color.BLACK)) {
            // 获取搜索文本
            String searchText = searchField.getText();

            // 创建行过滤器
            RowFilter<DefaultTableModel, Object> rowFilter;

            // 检查搜索模式是否为选中状态
            if (searchMode.isSelected()) {
                // 反向搜索：创建一个过滤器以排除与正则表达式匹配的行
                rowFilter = new RowFilter<DefaultTableModel, Object>() {
                    public boolean include(Entry<? extends DefaultTableModel, ? extends Object> entry) {
                        // 对每一行的第二列进行判断（假设第二列的索引是1）
                        String value = (String) entry.getValue(1);
                        // 如果该列的值不包含搜索文本，则返回true，否则返回false
                        return searchText.isEmpty() ? true : !value.toLowerCase().contains(searchText.toLowerCase());
                    }
                };
            } else {
                // 正向搜索：创建一个过滤器以包含与正则表达式匹配的行
                rowFilter = RowFilter.regexFilter("(?i)" + Pattern.quote(searchText), 1);
            }

            // 设置过滤器到排序器
            sorter.setRowFilter(rowFilter);
        }
    }

    // 加载指定页的数据
    private void loadPageData() {
        if (fullList.size() > SHOW_LENGTH && scrollFlag) {
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

    private static void addRowToTable(DefaultTableModel model, Object[] data) {
        // 获取当前ID
        int rowCount = model.getRowCount();
        int id = rowCount > 0 ? (Integer) model.getValueAt(rowCount - 1, 0) + 1 : 1;
        Object[] rowData = new Object[data.length + 1];
        rowData[0] = id; // 设置ID列的值
        System.arraycopy(data, 0, rowData, 1, data.length); // 拷贝其余数据
        model.addRow(rowData); // 添加行
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
        return Math.max(1, visibleHeight / rowHeight + 5);
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
        String revData = selectData.reverse().toString().replaceFirst("\n", "");
        StringBuilder retData = new StringBuilder(revData).reverse();
        return retData.toString();
    }

    public JTable getTable() {
        return this.table;
    }
}
