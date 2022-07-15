package burp.ui;

import burp.yaml.SetConfig;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.Vector;

/**
 * @author LinChen
 */

public class RulePane extends JPanel {
    public RulePane(Object[][] data, JTabbedPane pane) {
        initComponents(data, pane);
    }
    private SetConfig setConfig = new SetConfig();
    private Boolean isEdit = false;

    private void ruleAddActionPerformed(ActionEvent e, JTabbedPane pane) {
        RuleSetting ruleSettingPanel = new RuleSetting();
        int showState = JOptionPane.showConfirmDialog(null, ruleSettingPanel, "RuleSetting - Add Rule", JOptionPane.OK_OPTION);
        if(showState == 0){
            Vector ruleData = new Vector();
            ruleData.add(false);
            ruleData.add(ruleSettingPanel.ruleNameTextField.getText());
            ruleData.add(ruleSettingPanel.regexTextField.getText());
            ruleData.add(ruleSettingPanel.colorComboBox.getSelectedItem().toString());
            ruleData.add(ruleSettingPanel.scopeComboBox.getSelectedItem().toString());
            ruleData.add(ruleSettingPanel.engineComboBox.getSelectedItem().toString());
            ruleData.add(ruleSettingPanel.sensitiveComboBox.getSelectedItem());
            model.insertRow(model.getRowCount(), ruleData);
            model = (DefaultTableModel) ruleTable.getModel();
            setConfig.add(ruleData, pane.getTitleAt(pane.getSelectedIndex()));
        }
    }

    private void ruleEditActionPerformed(ActionEvent e, JTabbedPane pane){
        if (ruleTable.getSelectedRowCount() >= 1){
            RuleSetting ruleSettingPanel = new RuleSetting();
            ruleSettingPanel.ruleNameTextField.setText(ruleTable.getValueAt(ruleTable.getSelectedRow(), 1).toString());
            ruleSettingPanel.regexTextField.setText(ruleTable.getValueAt(ruleTable.getSelectedRow(), 2).toString());
            ruleSettingPanel.colorComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(), 3).toString());
            ruleSettingPanel.scopeComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(), 4).toString());
            ruleSettingPanel.engineComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(), 5).toString());
            ruleSettingPanel.sensitiveComboBox.setSelectedItem(ruleTable.getValueAt(ruleTable.getSelectedRow(),6));

            ruleSettingPanel.sensitiveComboBox.setEnabled(
                ruleSettingPanel.engineComboBox.getSelectedItem().toString().equals("nfa")
            );

            int showState = JOptionPane.showConfirmDialog(null, ruleSettingPanel, "RuleSetting - Edit Rule", JOptionPane.OK_OPTION);
            if (showState == 0){
                int select = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());
                model.setValueAt(ruleSettingPanel.ruleNameTextField.getText(), select, 1);
                model.setValueAt(ruleSettingPanel.regexTextField.getText(), select, 2);
                model.setValueAt(ruleSettingPanel.colorComboBox.getSelectedItem().toString(), select, 3);
                model.setValueAt(ruleSettingPanel.scopeComboBox.getSelectedItem().toString(), select, 4);
                model.setValueAt(ruleSettingPanel.engineComboBox.getSelectedItem().toString(), select, 5);
                model.setValueAt(ruleSettingPanel.sensitiveComboBox.getSelectedItem(), select, 6);
                model = (DefaultTableModel) ruleTable.getModel();
                setConfig.edit((Vector) model.getDataVector().get(select), select, pane.getTitleAt(pane.getSelectedIndex()));
            }
        }
    }

    private void ruleRemoveActionPerformed(ActionEvent e, JTabbedPane pane){
        if (ruleTable.getSelectedRowCount() >= 1){
            int isOk = JOptionPane.showConfirmDialog(null, "Are your sure?", "RuleSetting - Delete Rule", JOptionPane.OK_OPTION);
            if (isOk == 0){
                int select = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());
                model.removeRow(select);
                model = (DefaultTableModel) ruleTable.getModel();
                setConfig.remove(select, pane.getTitleAt(pane.getSelectedIndex()));
            }
        }
    }

    private void ruleTableChange(TableModelEvent e, JTabbedPane pane) {
        if (e.getColumn() == 0 && ruleTable.getSelectedRow() != -1 && !isEdit){
            model = (DefaultTableModel) ruleTable.getModel();
            int select = ruleTable.convertRowIndexToModel(ruleTable.getSelectedRow());
            setConfig.edit((Vector) model.getDataVector().get(select), select, pane.getTitleAt(pane.getSelectedIndex()));
        }
    }

    private void initComponents(Object[][] data, JTabbedPane pane) {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        addButton = new JButton();
        editButton = new JButton();
        scrollPane = new JScrollPane();
        ruleTable = new JTable();
        removeButton = new JButton();

        //======== this ========
        setLayout(new GridBagLayout());
        ((GridBagLayout)getLayout()).columnWidths = new int[] {0, 0, 0};
        ((GridBagLayout)getLayout()).rowHeights = new int[] {0, 0, 0, 0, 0};
        ((GridBagLayout)getLayout()).columnWeights = new double[] {0.0, 1.0, 1.0E-4};
        ((GridBagLayout)getLayout()).rowWeights = new double[] {0.0, 0.0, 0.0, 1.0, 1.0E-4};

        //---- addButton ----
        addButton.setText("Add");

        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isEdit = true;
                ruleAddActionPerformed(e, pane);
                model = (DefaultTableModel) ruleTable.getModel();
                isEdit = false;
            }
        });

        add(addButton, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(15, 5, 3, 2), 0, 0));

        //---- editButton ----
        editButton.setText("Edit");
        editButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isEdit = true;
                ruleEditActionPerformed(e, pane);
                model = (DefaultTableModel) ruleTable.getModel();
                isEdit = false;
            }
        });

        add(editButton, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 5, 3, 2), 0, 0));

        //======== scrollPane ========
        {
            //---- table ----
            ruleTable.setShowVerticalLines(false);
            ruleTable.setVerifyInputWhenFocusTarget(false);
            ruleTable.setUpdateSelectionOnSort(false);
            ruleTable.setShowHorizontalLines(false);
            ruleTable.setModel(new DefaultTableModel());
            ruleTable.setSurrendersFocusOnKeystroke(true);
            scrollPane.setViewportView(ruleTable);
        }

        add(scrollPane, new GridBagConstraints(1, 0, 1, 4, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(15, 5, 5, 5), 0, 0));

        //---- removeButton ----
        removeButton.setText("Remove");

        removeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                isEdit = true;
                ruleRemoveActionPerformed(e, pane);
                model = (DefaultTableModel) ruleTable.getModel();
                isEdit = false;
            }
        });

        add(removeButton, new GridBagConstraints(0, 2, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 5, 3, 2), 0, 0));

        // JFormDesigner - End of component initialization  //GEN-END:initComponents
        ruleTable.setModel(model);
        model.setDataVector(data, title);
        model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                ruleTableChange(e, pane);
            }
        });

        ruleTable.setRowSorter(new TableRowSorter(model));
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    public JButton addButton;
    public JButton editButton;
    public JScrollPane scrollPane;
    public JTable ruleTable;
    public JButton removeButton;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
    private final String[] title = new String[]{"Loaded", "Name", "Regex", "Color", "Scope", "Engine", "Sensitive"};
    private DefaultTableModel model = new DefaultTableModel() {
        @Override
        public Class<?> getColumnClass (int column){
            if (column == 0) {
                return Boolean.class;
            }else{
                return String.class;
            }
        }

        @Override
        public boolean isCellEditable(int row, int column){
            return column == 0;
        }
    };
}

