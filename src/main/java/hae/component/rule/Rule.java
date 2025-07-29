package hae.component.rule;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import hae.utils.ConfigLoader;
import hae.utils.rule.RuleProcessor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Vector;

import static javax.swing.JOptionPane.YES_OPTION;

public class Rule extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final RuleProcessor ruleProcessor;
    private final JTabbedPane tabbedPane;
    private JCheckBox headerCheckBox;

    public Rule(MontoyaApi api, ConfigLoader configLoader, Object[][] data, JTabbedPane tabbedPane) {
        this.api = api;
        this.configLoader = configLoader;
        this.ruleProcessor = new RuleProcessor(api, configLoader);
        this.tabbedPane = tabbedPane;

        initComponents(data);
    }

    private void initComponents(Object[][] data) {
        setLayout(new GridBagLayout());
        ((GridBagLayout) getLayout()).columnWidths = new int[]{0, 0, 0};
        ((GridBagLayout) getLayout()).rowHeights = new int[]{0, 0, 0, 0, 0};
        ((GridBagLayout) getLayout()).columnWeights = new double[]{0.0, 1.0, 1.0E-4};
        ((GridBagLayout) getLayout()).rowWeights = new double[]{0.0, 0.0, 0.0, 1.0, 1.0E-4};

        JButton copyButton = new JButton("Copy");
        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton removeButton = new JButton("Remove");

        JTable ruleTable = new JTable();
        JScrollPane scrollPane = new JScrollPane();

        ruleTable.setVerifyInputWhenFocusTarget(false);
        ruleTable.setUpdateSelectionOnSort(false);
        ruleTable.setSurrendersFocusOnKeystroke(true);
        scrollPane.setViewportView(ruleTable);

        // 按钮监听事件
        copyButton.addActionListener(e -> ruleCopyActionPerformed(e, ruleTable, tabbedPane));
        addButton.addActionListener(e -> ruleAddActionPerformed(e, ruleTable, tabbedPane));
        editButton.addActionListener(e -> ruleEditActionPerformed(e, ruleTable, tabbedPane));
        removeButton.addActionListener(e -> ruleRemoveActionPerformed(e, ruleTable, tabbedPane));

        // 表格
        DefaultTableModel model = new DefaultTableModel() {
            @Override
            public Class<?> getColumnClass(int column) {
                return (column == 0) ? Boolean.class : String.class;
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };

        ruleTable.setModel(model);
        ruleTable.setRowSorter(new TableRowSorter<>(model));

        model.setDataVector(data, Config.ruleFields);
        model.addTableModelListener(e -> {
            if (e.getColumn() == 0 && ruleTable.getSelectedRow() != -1) {
                int select = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());
                ruleProcessor.changeRule(model.getDataVector().get(select), select, tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()));

                // 更新表头复选框状态并强制重新渲染
                updateHeaderCheckBoxState(model);
                ruleTable.getTableHeader().repaint();
            }
        });

        // 设置表头复选框
        setupHeaderCheckBox(ruleTable);

        // 设置Loaded列的宽度（第一列）
        setupColumnWidths(ruleTable);

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.weightx = 1.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel buttonPanel = new JPanel();
        GridBagLayout layout = new GridBagLayout();
        layout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0};
        layout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        buttonPanel.setLayout(layout);

        constraints.insets = new Insets(0, 0, 3, 0);
        constraints.gridy = 0;
        buttonPanel.add(copyButton, constraints);
        constraints.gridy = 1;
        buttonPanel.add(addButton, constraints);
        constraints.gridy = 2;
        buttonPanel.add(editButton, constraints);
        constraints.gridy = 3;
        buttonPanel.add(removeButton, constraints);

        add(buttonPanel, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(15, 5, 3, 2), 0, 0));
        add(scrollPane, new GridBagConstraints(1, 0, 1, 4, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(15, 5, 5, 5), 0, 0));
    }

    /**
     * 设置列宽度
     */
    private void setupColumnWidths(JTable ruleTable) {
        // 设置Loaded列（第一列）的宽度
        ruleTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        ruleTable.getColumnModel().getColumn(0).setMaxWidth(50);
        ruleTable.getColumnModel().getColumn(0).setMinWidth(50);
    }

    /**
     * 设置表头复选框
     */
    private void setupHeaderCheckBox(JTable ruleTable) {
        // 创建表头复选框
        headerCheckBox = new JCheckBox();
        headerCheckBox.setHorizontalAlignment(SwingConstants.CENTER);

        // 设置表头渲染器
        ruleTable.getTableHeader().setDefaultRenderer(new HeaderCheckBoxRenderer(ruleTable.getTableHeader().getDefaultRenderer()));

        // 添加表头鼠标点击事件
        ruleTable.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1) {
                    JTableHeader header = (JTableHeader) e.getSource();
                    JTable table = header.getTable();
                    int columnIndex = header.columnAtPoint(e.getPoint());

                    if (columnIndex == 0) { // 点击的是Loaded列表头
                        toggleAllRules(table);
                    }
                }
            }
        });
    }

    /**
     * 自定义表头渲染器，在Loaded列显示复选框
     */
    private class HeaderCheckBoxRenderer implements TableCellRenderer {
        private final TableCellRenderer originalRenderer;

        public HeaderCheckBoxRenderer(TableCellRenderer originalRenderer) {
            this.originalRenderer = originalRenderer;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            if (column == 0) { // Loaded列
                // 获取原始表头组件作为背景
                Component originalComponent = originalRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                // 创建一个面板来包含复选框，保持原始样式
                JPanel panel = new JPanel(new BorderLayout());
                panel.setOpaque(true);

                // 复制原始组件的样式
                if (originalComponent instanceof JComponent) {
                    JComponent origComp = (JComponent) originalComponent;
                    panel.setBackground(origComp.getBackground());
                    panel.setBorder(origComp.getBorder());
                }

                // 更新复选框状态并添加到面板中心
                updateHeaderCheckBoxState((DefaultTableModel) table.getModel());
                headerCheckBox.setOpaque(false);  // 让复选框透明，显示背景
                panel.add(headerCheckBox, BorderLayout.CENTER);

                return panel;
            } else {
                return originalRenderer.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            }
        }
    }

    /**
     * 切换所有规则的开启/关闭状态
     */
    private void toggleAllRules(JTable ruleTable) {
        DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
        int rowCount = model.getRowCount();

        if (rowCount == 0) {
            return;
        }

        // 判断当前状态：如果所有规则都开启，则关闭所有；否则开启所有
        boolean allEnabled = true;
        for (int i = 0; i < rowCount; i++) {
            if (!(Boolean) model.getValueAt(i, 0)) {
                allEnabled = false;
                break;
            }
        }

        boolean newState = !allEnabled;

        // 更新所有行的状态
        for (int i = 0; i < rowCount; i++) {
            model.setValueAt(newState, i, 0);
            // 通知规则处理器更新规则状态
            ruleProcessor.changeRule(model.getDataVector().get(i), i, getCurrentTabTitle());
        }

        // 更新表头复选框状态
        updateHeaderCheckBoxState(model);

        // 刷新表格和表头
        ruleTable.repaint();
        ruleTable.getTableHeader().repaint();
    }

    /**
     * 更新表头复选框的状态
     */
    private void updateHeaderCheckBoxState(DefaultTableModel model) {
        int rowCount = model.getRowCount();
        if (rowCount == 0) {
            headerCheckBox.setSelected(false);
            headerCheckBox.getModel().setArmed(false);
            headerCheckBox.getModel().setPressed(false);
            return;
        }

        int enabledCount = 0;
        for (int i = 0; i < rowCount; i++) {
            if ((Boolean) model.getValueAt(i, 0)) {
                enabledCount++;
            }
        }

        if (enabledCount == 0) {
            // 全部未选中
            headerCheckBox.setSelected(false);
            headerCheckBox.getModel().setArmed(false);
            headerCheckBox.getModel().setPressed(false);
        } else if (enabledCount == rowCount) {
            // 全部选中
            headerCheckBox.setSelected(true);
            headerCheckBox.getModel().setArmed(false);
            headerCheckBox.getModel().setPressed(false);
        } else {
            // 部分选中 - 显示为按下但未选中的状态
            headerCheckBox.setSelected(false);
            headerCheckBox.getModel().setArmed(true);
            headerCheckBox.getModel().setPressed(true);
        }
    }

    /**
     * 填充Display对象的字段值
     */
    private void populateDisplayFromTable(Display ruleDisplay, JTable ruleTable, int selectedRow) {
        ruleDisplay.ruleNameTextField.setText(ruleTable.getValueAt(selectedRow, 1).toString());
        ruleDisplay.firstRegexTextField.setText(ruleTable.getValueAt(selectedRow, 2).toString());
        ruleDisplay.secondRegexTextField.setText(ruleTable.getValueAt(selectedRow, 3).toString());
        ruleDisplay.formatTextField.setText(ruleTable.getValueAt(selectedRow, 4).toString());
        ruleDisplay.colorComboBox.setSelectedItem(ruleTable.getValueAt(selectedRow, 5).toString());
        ruleDisplay.scopeComboBox.setSelectedItem(ruleTable.getValueAt(selectedRow, 6).toString());
        ruleDisplay.engineComboBox.setSelectedItem(ruleTable.getValueAt(selectedRow, 7).toString());
        ruleDisplay.sensitiveComboBox.setSelectedItem(ruleTable.getValueAt(selectedRow, 8));
    }

    /**
     * 从Display对象创建规则数据Vector
     */
    private Vector<Object> createRuleDataFromDisplay(Display ruleDisplay) {
        Vector<Object> ruleData = new Vector<>();
        ruleData.add(false);
        ruleData.add(ruleDisplay.ruleNameTextField.getText());
        ruleData.add(ruleDisplay.firstRegexTextField.getText());
        ruleData.add(ruleDisplay.secondRegexTextField.getText());
        ruleData.add(ruleDisplay.formatTextField.getText());
        ruleData.add(ruleDisplay.colorComboBox.getSelectedItem().toString());
        ruleData.add(ruleDisplay.scopeComboBox.getSelectedItem().toString());
        ruleData.add(ruleDisplay.engineComboBox.getSelectedItem().toString());
        ruleData.add(ruleDisplay.sensitiveComboBox.getSelectedItem());
        return ruleData;
    }

    /**
     * 显示规则编辑对话框
     */
    private boolean showRuleDialog(Display ruleDisplay, String title) {
        ruleDisplay.formatTextField.setEnabled(ruleDisplay.engineComboBox.getSelectedItem().toString().equals("nfa"));
        int showState = JOptionPane.showConfirmDialog(this, ruleDisplay, title, JOptionPane.YES_NO_OPTION);
        return showState == YES_OPTION;
    }

    /**
     * 检查是否有选中的行
     */
    private boolean hasSelectedRow(JTable ruleTable) {
        return ruleTable.getSelectedRowCount() >= 1;
    }

    /**
     * 获取当前选中的Tab标题
     */
    private String getCurrentTabTitle() {
        return tabbedPane.getTitleAt(tabbedPane.getSelectedIndex());
    }

    private void ruleCopyActionPerformed(ActionEvent e, JTable ruleTable, JTabbedPane tabbedPane) {
        if (!hasSelectedRow(ruleTable)) {
            return;
        }

        Display ruleDisplay = new Display();
        int selectedRow = ruleTable.getSelectedRow();

        populateDisplayFromTable(ruleDisplay, ruleTable, selectedRow);
        // 为复制的规则名称添加前缀
        ruleDisplay.ruleNameTextField.setText(String.format("Copy of %s", ruleDisplay.ruleNameTextField.getText()));

        if (showRuleDialog(ruleDisplay, "Copy Rule")) {
            Vector<Object> ruleData = createRuleDataFromDisplay(ruleDisplay);
            DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
            model.insertRow(model.getRowCount(), ruleData);
            ruleProcessor.addRule(ruleData, getCurrentTabTitle());

            // 复制规则后更新表头复选框状态
            updateHeaderCheckBoxState(model);
            ruleTable.getTableHeader().repaint();
        }
    }

    private void ruleAddActionPerformed(ActionEvent e, JTable ruleTable, JTabbedPane tabbedPane) {
        Display ruleDisplay = new Display();
        ruleDisplay.formatTextField.setText("{0}");

        if (showRuleDialog(ruleDisplay, "Add Rule")) {
            Vector<Object> ruleData = createRuleDataFromDisplay(ruleDisplay);
            DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
            model.insertRow(model.getRowCount(), ruleData);
            ruleProcessor.addRule(ruleData, getCurrentTabTitle());

            // 添加规则后更新表头复选框状态
            updateHeaderCheckBoxState(model);
            ruleTable.getTableHeader().repaint();
        }
    }

    private void ruleEditActionPerformed(ActionEvent e, JTable ruleTable, JTabbedPane tabbedPane) {
        if (!hasSelectedRow(ruleTable)) {
            return;
        }

        Display ruleDisplay = new Display();
        int selectedRow = ruleTable.getSelectedRow();

        populateDisplayFromTable(ruleDisplay, ruleTable, selectedRow);

        if (showRuleDialog(ruleDisplay, "Edit Rule")) {
            DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
            int modelIndex = ruleTable.convertRowIndexToModel(selectedRow);

            // 更新表格数据
            Vector<Object> ruleData = createRuleDataFromDisplay(ruleDisplay);
            for (int i = 1; i < ruleData.size(); i++) {
                model.setValueAt(ruleData.get(i), modelIndex, i);
            }

            ruleProcessor.changeRule(model.getDataVector().get(modelIndex), modelIndex, getCurrentTabTitle());

            // 编辑规则后更新表头复选框状态（如果编辑影响了启用状态）
            updateHeaderCheckBoxState(model);
            ruleTable.getTableHeader().repaint();
        }
    }

    private void ruleRemoveActionPerformed(ActionEvent e, JTable ruleTable, JTabbedPane tabbedPane) {
        if (!hasSelectedRow(ruleTable)) {
            return;
        }

        if (JOptionPane.showConfirmDialog(this, "Are you sure you want to remove this rule?", "Info", JOptionPane.YES_NO_OPTION) == 0) {
            DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
            int select = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());

            model.removeRow(select);
            ruleProcessor.removeRule(select, getCurrentTabTitle());

            // 删除规则后更新表头复选框状态
            updateHeaderCheckBoxState(model);
            ruleTable.getTableHeader().repaint();
        }
    }
}