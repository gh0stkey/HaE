package hae.component.rule;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import hae.utils.ConfigLoader;
import hae.utils.rule.RuleProcessor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Vector;

import static javax.swing.JOptionPane.YES_OPTION;

public class Rule extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final RuleProcessor ruleProcessor;
    private final JTabbedPane tabbedPane;

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

        JButton addButton = new JButton("Add");
        JButton editButton = new JButton("Edit");
        JButton removeButton = new JButton("Remove");

        JTable ruleTable = new JTable();
        JScrollPane scrollPane = new JScrollPane();

        ruleTable.setShowVerticalLines(false);
        ruleTable.setShowHorizontalLines(false);
        ruleTable.setVerifyInputWhenFocusTarget(false);
        ruleTable.setUpdateSelectionOnSort(false);
        ruleTable.setSurrendersFocusOnKeystroke(true);
        scrollPane.setViewportView(ruleTable);

        // 按钮监听事件
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
            }
        });

        add(addButton, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(15, 5, 3, 2), 0, 0));
        add(editButton, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 5, 3, 2), 0, 0));
        add(removeButton, new GridBagConstraints(0, 2, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 5, 3, 2), 0, 0));
        add(scrollPane, new GridBagConstraints(1, 0, 1, 4, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(15, 5, 5, 5), 0, 0));
    }

    private void ruleAddActionPerformed(ActionEvent e, JTable ruleTable, JTabbedPane tabbedPane) {
        Display ruleDisplay = new Display();
        ruleDisplay.formatTextField.setText("{0}");

        int showState = JOptionPane.showConfirmDialog(null, ruleDisplay, "Add Rule", JOptionPane.OK_OPTION);
        if (showState == YES_OPTION) {
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

            DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
            model.insertRow(model.getRowCount(), ruleData);
            ruleProcessor.addRule(ruleData, tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()));
        }
    }

    private void ruleEditActionPerformed(ActionEvent e, JTable ruleTable, JTabbedPane tabbedPane) {
        if (ruleTable.getSelectedRowCount() >= 1) {
            DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
            Display ruleDisplay = new Display();

            ruleDisplay.ruleNameTextField.setText(ruleTable.getValueAt(ruleTable.getSelectedRow(), 1).toString());
            ruleDisplay.firstRegexTextField.setText(ruleTable.getValueAt(ruleTable.getSelectedRow(), 2).toString());
            ruleDisplay.secondRegexTextField.setText(ruleTable.getValueAt(ruleTable.getSelectedRow(), 3).toString());
            ruleDisplay.formatTextField.setText(ruleTable.getValueAt(ruleTable.getSelectedRow(), 4).toString());
            ruleDisplay.colorComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(), 5).toString());
            ruleDisplay.scopeComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(), 6).toString());
            ruleDisplay.engineComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(), 7).toString());
            ruleDisplay.sensitiveComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(), 8));

            ruleDisplay.formatTextField.setEnabled(ruleDisplay.engineComboBox.getSelectedItem().toString().equals("nfa"));

            int showState = JOptionPane.showConfirmDialog(null, ruleDisplay, "Edit Rule", JOptionPane.OK_OPTION);
            if (showState == 0) {
                int select = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());
                model.setValueAt(ruleDisplay.ruleNameTextField.getText(), select, 1);
                model.setValueAt(ruleDisplay.firstRegexTextField.getText(), select, 2);
                model.setValueAt(ruleDisplay.secondRegexTextField.getText(), select, 3);
                model.setValueAt(ruleDisplay.formatTextField.getText(), select, 4);
                model.setValueAt(ruleDisplay.colorComboBox.getSelectedItem().toString(), select, 5);
                model.setValueAt(ruleDisplay.scopeComboBox.getSelectedItem().toString(), select, 6);
                model.setValueAt(ruleDisplay.engineComboBox.getSelectedItem().toString(), select, 7);
                model.setValueAt(ruleDisplay.sensitiveComboBox.getSelectedItem(), select, 8);
                model = (DefaultTableModel) ruleTable.getModel();
                ruleProcessor.changeRule(model.getDataVector().get(select), select, tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()));
            }
        }
    }

    private void ruleRemoveActionPerformed(ActionEvent e, JTable ruleTable, JTabbedPane tabbedPane) {
        if (ruleTable.getSelectedRowCount() >= 1) {
            if (JOptionPane.showConfirmDialog(null, "Are you sure you want to remove this rule?", "Info", JOptionPane.YES_NO_OPTION) == 0) {
                DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
                int select = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());

                model.removeRow(select);
                ruleProcessor.removeRule(select, tabbedPane.getTitleAt(tabbedPane.getSelectedIndex()));
            }
        }
    }
}