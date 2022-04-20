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

/*
 * @author LinChen
 */

public class RulePane extends JPanel {
    public RulePane(Object[][] data,JTabbedPane pane) {
        initComponents(data,pane);
    }
    private SetConfig setruleconfig = new SetConfig();
    private Boolean isEdit = false;
    private void RuleAddMouseClicked(MouseEvent e, JTabbedPane pane) {
        RuleSetting add = new RuleSetting();
        int isOk = JOptionPane.showConfirmDialog(null,add,"RuleSetting - Add Rule",JOptionPane.OK_OPTION);
        if(isOk == 0){
            Vector data = new Vector();
            data.add(false);
            data.add(add.Name.getText());
            data.add(add.Regex.getText());
            data.add(add.ColorSelect.getSelectedItem().toString());
            data.add(add.ScopeSelect.getSelectedItem().toString());
            data.add(add.EngineSelect.getSelectedItem().toString());
            model.insertRow(model.getRowCount(),data);
            model = (DefaultTableModel) table.getModel();
            setruleconfig.add(data,pane.getTitleAt(pane.getSelectedIndex()));
        }
    }

    private void RuleEditMouseClicked(MouseEvent e,JTabbedPane pane){
        if (table.getSelectedRowCount()>=1){
            RuleSetting edit = new RuleSetting();
            edit.Name.setText(table.getValueAt(table.getSelectedRow(),1).toString());
            edit.Regex.setText(table.getValueAt(table.getSelectedRow(),2).toString());
            edit.ColorSelect.setSelectedItem(table.getValueAt(table.getSelectedRow(),3).toString());
            edit.ScopeSelect.setSelectedItem(table.getValueAt(table.getSelectedRow(),4).toString());
            edit.EngineSelect.setSelectedItem(table.getValueAt(table.getSelectedRow(),5).toString());
            int isOk = JOptionPane.showConfirmDialog(null,edit,"RuleSetting - Edit Rule",JOptionPane.OK_OPTION);
            if (isOk ==0){
                int select = table.convertRowIndexToModel(table.getSelectedRow());
                model.setValueAt(edit.Name.getText(),select,1);
                model.setValueAt(edit.Regex.getText(),select,2);
                model.setValueAt(edit.ColorSelect.getSelectedItem().toString(),select,3);
                model.setValueAt(edit.ScopeSelect.getSelectedItem().toString(),select,4);
                model.setValueAt(edit.EngineSelect.getSelectedItem().toString(),select,5);
                model = (DefaultTableModel) table.getModel();
                setruleconfig.edit((Vector) model.getDataVector().get(select),select,pane.getTitleAt(pane.getSelectedIndex()));
            }
        }
    }

    private void RuleRemoveMouseClicked(MouseEvent e,JTabbedPane pane){
        if (table.getSelectedRowCount()>=1){
            int isOk = JOptionPane.showConfirmDialog(null,"Are your sure?","RuleSetting - Delete Rule",JOptionPane.OK_OPTION);
            if (isOk==0){
                int select = table.convertRowIndexToModel(table.getSelectedRow());
                model.removeRow(select);
                model = (DefaultTableModel) table.getModel();
                setruleconfig.remove(select,pane.getTitleAt(pane.getSelectedIndex()));
            }
        }
    }

    private void RuleTableChange(TableModelEvent e,JTabbedPane pane) {
        if (e.getColumn()==0&&table.getSelectedRow()!=-1&&!isEdit){
            model = (DefaultTableModel) table.getModel();
            int select = table.convertRowIndexToModel(table.getSelectedRow());
            setruleconfig.edit((Vector) model.getDataVector().get(select),select,pane.getTitleAt(pane.getSelectedIndex()));
        }
    }

    private void initComponents(Object[][] data,JTabbedPane pane) {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        RuleAdd = new JButton();
        RuleEdit = new JButton();
        scrollPane = new JScrollPane();
        table = new JTable();
        Remove = new JButton();

        //======== this ========
        setLayout(new GridBagLayout());
        ((GridBagLayout)getLayout()).columnWidths = new int[] {0, 0, 0};
        ((GridBagLayout)getLayout()).rowHeights = new int[] {0, 0, 0, 0, 0};
        ((GridBagLayout)getLayout()).columnWeights = new double[] {0.0, 1.0, 1.0E-4};
        ((GridBagLayout)getLayout()).rowWeights = new double[] {0.0, 0.0, 0.0, 1.0, 1.0E-4};

        //---- RuleAdd ----
        RuleAdd.setText("Add");
        RuleAdd.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                isEdit = true;
                RuleAddMouseClicked(e,pane);
                model = (DefaultTableModel) table.getModel();
                isEdit = false;
            }
        });
        add(RuleAdd, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
            GridBagConstraints.CENTER, GridBagConstraints.BOTH,
            new Insets(15, 5, 3, 2), 0, 0));

        //---- RuleEdit ----
        RuleEdit.setText("Edit");
        RuleEdit.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                isEdit = true;
                RuleEditMouseClicked(e,pane);
                model = (DefaultTableModel) table.getModel();
                isEdit = false;
            }
        });
        add(RuleEdit, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0,
            GridBagConstraints.CENTER, GridBagConstraints.BOTH,
            new Insets(0, 5, 3, 2), 0, 0));

        //======== scrollPane ========
        {

            //---- table ----
            table.setShowVerticalLines(false);
            table.setVerifyInputWhenFocusTarget(false);
            table.setUpdateSelectionOnSort(false);
            table.setShowHorizontalLines(false);
            table.setModel(new DefaultTableModel());
            table.setSurrendersFocusOnKeystroke(true);
            scrollPane.setViewportView(table);
        }
        add(scrollPane, new GridBagConstraints(1, 0, 1, 4, 0.0, 0.0,
            GridBagConstraints.CENTER, GridBagConstraints.BOTH,
            new Insets(15, 5, 5, 5), 0, 0));

        //---- Remove ----
        Remove.setText("Remove");
        Remove.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                isEdit = true;
                RuleRemoveMouseClicked(e,pane);
                model = (DefaultTableModel) table.getModel();
                isEdit = false;
            }
        });
        add(Remove, new GridBagConstraints(0, 2, 1, 1, 0.0, 0.0,
            GridBagConstraints.CENTER, GridBagConstraints.BOTH,
            new Insets(0, 5, 3, 2), 0, 0));
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
        table.setModel(model);
        model.setDataVector(data,title);
        model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                RuleTableChange(e,pane);
            }
        });
        table.setRowSorter(new TableRowSorter(model));
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    public JButton RuleAdd;
    public JButton RuleEdit;
    public JScrollPane scrollPane;
    public JTable table;
    public JButton Remove;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
    private final String[] title = new String[]{"Loaded", "Name", "Regex", "Color", "Scope", "Engine"};
    private DefaultTableModel model = new DefaultTableModel() {
        @Override
        public Class<?> getColumnClass ( int column){
            if (column == 0) {
                return Boolean.class;
            }else{
                return String.class;
            }
        }

        @Override
        public boolean isCellEditable(int row,int column){
            if (column ==0){
                return true;
            }else {
                return false;
            }
        }
    };
}

