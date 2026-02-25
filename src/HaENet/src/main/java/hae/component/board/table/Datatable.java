package hae.component.board.table;

import burp.api.montoya.MontoyaApi;
import hae.component.board.message.MessageTableModel;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.UIEnhancer;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
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
    private final JCheckBox regexMode = new JCheckBox("Regex mode");
    private final String tabName;
    private final JPanel footerPanel;
    private final ValidatorService validatorService;
    private final Set<String> selectedSeverities = new LinkedHashSet<>(List.of(
            ValidatorService.SEVERITY_HIGH, ValidatorService.SEVERITY_MEDIUM,
            ValidatorService.SEVERITY_LOW, ValidatorService.SEVERITY_NONE
    ));
    private SwingWorker<Void, Void> doubleClickWorker;

    public Datatable(MontoyaApi api, ConfigLoader configLoader, String tabName, List<String> dataList,
                     ValidatorService validatorService) {
        this.api = api;
        this.configLoader = configLoader;
        this.tabName = tabName;
        this.validatorService = validatorService;

        String[] columnNames = {"#", "Information", "Severity"};
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
        sorter.setComparator(0, (Comparator<Integer>) Integer::compareTo);

        // 设置Severity排序
        sorter.setComparator(2, (Comparator<String>) ValidatorService::compareBySeverity);

        for (String item : dataList) {
            if (!item.isEmpty()) {
                String severity = validatorService != null ? validatorService.getSeverity(tabName, item) : null;
                addRowToTable(new Object[]{item, severity != null ? severity : ValidatorService.SEVERITY_NONE});
            }
        }

        // 默认按Severity排序（高到低）
        sorter.toggleSortOrder(2);

        // 自动触发验证
        if (validatorService != null) {
            List<String> allMatches = new ArrayList<>();
            for (int i = 0; i < dataTableModel.getRowCount(); i++) {
                allMatches.add((String) dataTableModel.getValueAt(i, 1));
            }
            if (!allMatches.isEmpty()) {
                validatorService.autoValidate(Map.of(tabName, allMatches), null, () ->
                        SwingUtilities.invokeLater(this::refreshSeverities)
                );
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

        TableColumn severityColumn = dataTable.getColumnModel().getColumn(2);
        severityColumn.setPreferredWidth(80);
        severityColumn.setMaxWidth(100);
        severityColumn.setCellRenderer(new SeverityBadgeRenderer());

        if (validatorService != null) {
            JPopupMenu rowPopup = new JPopupMenu();
            JMenuItem revalidateItem = new JMenuItem("Revalidate");
            revalidateItem.addActionListener(e -> revalidateSelectedRows());
            rowPopup.add(revalidateItem);

            JMenu severityMenu = new JMenu("Set Severity");
            for (String level : ValidatorService.SEVERITY_LEVELS) {
                JMenuItem item = new JMenuItem(level.substring(0, 1).toUpperCase() + level.substring(1));
                item.setForeground(getSeverityColor(level));
                item.addActionListener(e -> setSelectedRowsSeverity(level));
                severityMenu.add(item);
            }
            rowPopup.add(severityMenu);

            dataTable.addMouseListener(new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    showPopupIfNeeded(e);
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    showPopupIfNeeded(e);
                }

                private void showPopupIfNeeded(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        int row = dataTable.rowAtPoint(e.getPoint());
                        if (row >= 0 && !dataTable.isRowSelected(row)) {
                            dataTable.setRowSelectionInterval(row, row);
                        }
                        if (dataTable.getSelectedRowCount() > 0) {
                            rowPopup.show(dataTable, e.getX(), e.getY());
                        }
                    }
                }
            });
        }

        setLayout(new BorderLayout(0, 5));

        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.X_AXIS));

        // Settings按钮
        JPanel settingMenuPanel = new JPanel(new GridLayout(2, 1));
        settingMenuPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JPopupMenu settingMenu = new JPopupMenu();
        settingMenuPanel.add(searchMode);
        settingMenuPanel.add(regexMode);
        regexMode.setSelected(true);
        searchMode.addItemListener(e -> performSearch());
        settingMenu.add(settingMenuPanel);

        JButton settingsButton = new JButton("Settings");
        setMenuShow(settingMenu, settingsButton);

        // Severity filter toggles
        JPanel severityPanel = new JPanel();
        severityPanel.setLayout(new BoxLayout(severityPanel, BoxLayout.X_AXIS));
        for (String level : ValidatorService.SEVERITY_LEVELS) {
            Color levelColor = getSeverityColor(level);
            JToggleButton btn = new JToggleButton(level.substring(0, 1).toUpperCase(), true) {
                @Override
                protected void paintComponent(Graphics g) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    if (isSelected()) {
                        g2.setColor(levelColor);
                        g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                        g2.setColor(Color.WHITE);
                    } else {
                        g2.setColor(getParent().getBackground());
                        g2.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                        g2.setColor(levelColor);
                        g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                    }
                    g2.setFont(getFont());
                    FontMetrics fm = g2.getFontMetrics();
                    String text = getText();
                    int x = (getWidth() - fm.stringWidth(text)) / 2;
                    int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
                    g2.drawString(text, x, y);
                    g2.dispose();
                }
            };
            btn.setToolTipText(level);
            btn.setPreferredSize(new Dimension(26, 20));
            btn.setMaximumSize(new Dimension(26, 20));
            btn.setFont(btn.getFont().deriveFont(Font.BOLD, 11f));
            btn.setFocusPainted(false);
            btn.setBorderPainted(false);
            btn.setContentAreaFilled(false);
            btn.addActionListener(e -> {
                if (btn.isSelected()) {
                    selectedSeverities.add(level);
                } else {
                    selectedSeverities.remove(level);
                }
                performSearch();
            });
            severityPanel.add(btn);
            severityPanel.add(Box.createHorizontalStrut(2));
        }

        optionsPanel.add(settingsButton);
        optionsPanel.add(Box.createHorizontalStrut(5));
        optionsPanel.add(severityPanel);
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
        List<RowFilter<Object, Object>> filters = new ArrayList<>();

        // Severity filter
        filters.add(new RowFilter<>() {
            public boolean include(Entry<?, ?> entry) {
                String severity = entry.getValue(2).toString();
                return selectedSeverities.contains(severity);
            }
        });

        if (UIEnhancer.hasUserInput(searchField)) {
            filters.add(getObjectObjectRowFilter(searchField, true));
        }

        if (UIEnhancer.hasUserInput(secondSearchField)) {
            filters.add(getObjectObjectRowFilter(secondSearchField, false));
        }

        sorter.setRowFilter(RowFilter.andFilter(filters));
    }

    private RowFilter<Object, Object> getObjectObjectRowFilter(JTextField searchField, boolean isReversible) {
        return new RowFilter<>() {
            public boolean include(Entry<?, ?> entry) {
                String searchText = searchField.getText();
                searchText = searchText.toLowerCase();
                String entryValue = ((String) entry.getValue(1)).toLowerCase();
                boolean filterReturn = searchText.isEmpty();
                boolean reverseReturn = searchMode.isSelected() && isReversible;
                if (regexMode.isSelected()) {
                    Pattern pattern = null;
                    try {
                        pattern = Pattern.compile(searchText, Pattern.CASE_INSENSITIVE);
                    } catch (Exception ignored) {
                    }

                    if (pattern != null) {
                        filterReturn = filterReturn || pattern.matcher(entryValue).find() != reverseReturn;
                    }
                } else {
                    filterReturn = filterReturn || entryValue.contains(searchText) != reverseReturn;
                }

                return filterReturn;
            }
        };
    }

    private void handleDoubleClick(int selectedRow, MessageTableModel messagePanel) {
        if (doubleClickWorker != null && !doubleClickWorker.isDone()) {
            doubleClickWorker.cancel(true);
        }

        // 在EDT上读取表格数据（Swing线程安全）
        String rowData = dataTable.getValueAt(selectedRow, 1).toString();

        doubleClickWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                if (!isCancelled()) {
                    // 在后台线程执行过滤，applyMessageFilter内部已通过invokeLater更新UI
                    messagePanel.applyMessageFilter(tabName, rowData);
                }
                return null;
            }
        };
        doubleClickWorker.execute();
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
                        handleDoubleClick(selectedRow, messagePanel);
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

    public String getTabName() {
        return this.tabName;
    }

    public void refreshSeverities() {
        for (int i = 0; i < dataTableModel.getRowCount(); i++) {
            String matchValue = (String) dataTableModel.getValueAt(i, 1);
            String severity = validatorService != null ? validatorService.getSeverity(tabName, matchValue) : null;
            dataTableModel.setValueAt(severity != null ? severity : ValidatorService.SEVERITY_NONE, i, 2);
        }
        sorter.sort();
    }

    private void revalidateSelectedRows() {
        if (validatorService == null) return;
        int[] selectedRows = dataTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        List<String> matches = new ArrayList<>();
        for (int row : selectedRows) {
            matches.add(dataTable.getValueAt(row, 1).toString());
        }

        validatorService.revalidateAll(Map.of(tabName, matches), null, () ->
                SwingUtilities.invokeLater(this::refreshSeverities)
        );
    }

    private void setSelectedRowsSeverity(String severity) {
        if (validatorService == null) return;
        int[] selectedRows = dataTable.getSelectedRows();
        if (selectedRows.length == 0) return;

        for (int row : selectedRows) {
            int modelRow = dataTable.convertRowIndexToModel(row);
            String matchValue = (String) dataTableModel.getValueAt(modelRow, 1);
            validatorService.setSeverity(tabName, matchValue, severity);
            dataTableModel.setValueAt(severity, modelRow, 2);
        }
        validatorService.persistRule(tabName);
        sorter.sort();
    }

    private static Color getSeverityColor(String severity) {
        return switch (severity) {
            case ValidatorService.SEVERITY_HIGH -> new Color(220, 50, 50);
            case ValidatorService.SEVERITY_MEDIUM -> new Color(220, 150, 30);
            case ValidatorService.SEVERITY_LOW -> new Color(60, 130, 220);
            default -> Color.GRAY;
        };
    }

    private static class SeverityBadgeRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            String severity = value != null ? value.toString() : ValidatorService.SEVERITY_NONE;
            label.setText(severity.substring(0, 1).toUpperCase());
            label.setHorizontalAlignment(SwingConstants.CENTER);
            if (!isSelected) {
                label.setForeground(getSeverityColor(severity));
            }
            label.setFont(label.getFont().deriveFont(Font.BOLD));
            return label;
        }
    }
}

