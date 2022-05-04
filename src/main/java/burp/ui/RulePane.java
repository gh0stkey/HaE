package burp.ui;

import burp.yaml.SetConfig;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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

    private void ruleAddMouseClicked(MouseEvent e, JTabbedPane pane) {
        RuleSetting add = new RuleSetting();
        int isOk = JOptionPane.showConfirmDialog(null, add, "RuleSetting - Add Rule", JOptionPane.OK_OPTION);
        if(isOk == 0){
            Vector data = new Vector();
            data.add(false);
            data.add(add.Name.getText());
            data.add(add.Regex.getText());
            data.add(add.ColorSelect.getSelectedItem().toString());
            data.add(add.ScopeSelect.getSelectedItem().toString());
            data.add(add.EngineSelect.getSelectedItem().toString());
            model.insertRow(model.getRowCount(), data);
            model = (DefaultTableModel) jTable.getModel();
            setConfig.add(data, pane.getTitleAt(pane.getSelectedIndex()));
        }
    }

    private void ruleEditMouseClicked(MouseEvent e, JTabbedPane pane){
        if (jTable.getSelectedRowCount() >= 1){
            RuleSetting edit = new RuleSetting();
            edit.Name.setText(jTable.getValueAt(jTable.getSelectedRow(), 1).toString());
            edit.Regex.setText(jTable.getValueAt(jTable.getSelectedRow(), 2).toString());
            edit.ColorSelect.setSelectedItem(jTable.getValueAt(jTable.getSelectedRow(), 3).toString());
            edit.ScopeSelect.setSelectedItem(jTable.getValueAt(jTable.getSelectedRow(), 4).toString());
            edit.EngineSelect.setSelectedItem(jTable.getValueAt(jTable.getSelectedRow(), 5).toString());
            int isOk = JOptionPane.showConfirmDialog(null, edit, "RuleSetting - Edit Rule", JOptionPane.OK_OPTION);
            if (isOk == 0){
                int select = jTable.convertRowIndexToModel(jTable.getSelectedRow());
                model.setValueAt(edit.Name.getText(), select, 1);
                model.setValueAt(edit.Regex.getText(), select, 2);
                model.setValueAt(edit.ColorSelect.getSelectedItem().toString(), select, 3);
                model.setValueAt(edit.ScopeSelect.getSelectedItem().toString(), select, 4);
                model.setValueAt(edit.EngineSelect.getSelectedItem().toString(), select, 5);
                model = (DefaultTableModel) jTable.getModel();
                setConfig.edit((Vector) model.getDataVector().get(select), select, pane.getTitleAt(pane.getSelectedIndex()));
            }
        }
    }

    private void ruleRemoveMouseClicked(MouseEvent e, JTabbedPane pane){
        if (jTable.getSelectedRowCount() >= 1){
            int isOk = JOptionPane.showConfirmDialog(null, "Are your sure?", "RuleSetting - Delete Rule", JOptionPane.OK_OPTION);
            if (isOk == 0){
                int select = jTable.convertRowIndexToModel(jTable.getSelectedRow());
                model.removeRow(select);
                model = (DefaultTableModel) jTable.getModel();
                setConfig.remove(select, pane.getTitleAt(pane.getSelectedIndex()));
            }
        }
    }

    private void ruleTableChange(TableModelEvent e, JTabbedPane pane) {
        if (e.getColumn() == 0 && jTable.getSelectedRow() != -1 && !isEdit){
            model = (DefaultTableModel) jTable.getModel();
            int select = jTable.convertRowIndexToModel(jTable.getSelectedRow());
            setConfig.edit((Vector) model.getDataVector().get(select), select, pane.getTitleAt(pane.getSelectedIndex()));
        }
    }

    private void initComponents(Object[][] data, JTabbedPane pane) {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        addButton = new JButton();
        editButton = new JButton();
        scrollPane = new JScrollPane();
        jTable = new JTable();
        removeButton = new JButton();

        //======== this ========
        setLayout(new GridBagLayout());
        ((GridBagLayout)getLayout()).columnWidths = new int[] {0, 0, 0};
        ((GridBagLayout)getLayout()).rowHeights = new int[] {0, 0, 0, 0, 0};
        ((GridBagLayout)getLayout()).columnWeights = new double[] {0.0, 1.0, 1.0E-4};
        ((GridBagLayout)getLayout()).rowWeights = new double[] {0.0, 0.0, 0.0, 1.0, 1.0E-4};

        //---- addButton ----
        addButton.setText("Add");

        addButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                isEdit = true;
                ruleAddMouseClicked(e, pane);
                model = (DefaultTableModel) jTable.getModel();
                isEdit = false;
            }
        });

        add(addButton, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0, 
            GridBagConstraints.CENTER, GridBagConstraints.BOTH, 
            new Insets(15, 5, 3, 2), 0, 0));

        //---- editButton ----
        editButton.setText("Edit");
        editButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                isEdit = true;
                ruleEditMouseClicked(e, pane);
                model = (DefaultTableModel) jTable.getModel();
                isEdit = false;
            }
        });

        add(editButton, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0, 
            GridBagConstraints.CENTER, GridBagConstraints.BOTH, 
            new Insets(0, 5, 3, 2), 0, 0));

        //======== scrollPane ========
        {
            //---- table ----
            jTable.setShowVerticalLines(false);
            jTable.setVerifyInputWhenFocusTarget(false);
            jTable.setUpdateSelectionOnSort(false);
            jTable.setShowHorizontalLines(false);
            jTable.setModel(new DefaultTableModel());
            jTable.setSurrendersFocusOnKeystroke(true);
            scrollPane.setViewportView(jTable);
        }

        add(scrollPane, new GridBagConstraints(1, 0, 1, 4, 0.0, 0.0, 
            GridBagConstraints.CENTER, GridBagConstraints.BOTH, 
            new Insets(15, 5, 5, 5), 0, 0));

        //---- removeButton ----
        removeButton.setText("Remove");

        removeButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                isEdit = true;
                ruleRemoveMouseClicked(e, pane);
                model = (DefaultTableModel) jTable.getModel();
                isEdit = false;
            }
        });

        add(removeButton, new GridBagConstraints(0, 2, 1, 1, 0.0, 0.0, 
            GridBagConstraints.CENTER, GridBagConstraints.BOTH, 
            new Insets(0, 5, 3, 2), 0, 0));

        // JFormDesigner - End of component initialization  //GEN-END:initComponents
        jTable.setModel(model);
        model.setDataVector(data, title);
        model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                ruleTableChange(e, pane);
            }
        });

        jTable.setRowSorter(new TableRowSorter(model));
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    public JButton addButton;
    public JButton editButton;
    public JScrollPane scrollPane;
    public JTable jTable;
    public JButton removeButton;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
    private final String[] title = new String[]{"Loaded", "Name", "Regex", "Color", "Scope", "Engine"};
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

