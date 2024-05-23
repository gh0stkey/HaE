package hae.component.config;

import burp.api.montoya.MontoyaApi;
import hae.component.rule.Rules;
import hae.utils.config.ConfigLoader;
import hae.utils.ui.UIEnhancer;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class Config extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final Rules rules;

    public Config(MontoyaApi api, ConfigLoader configLoader, Rules rules) {
        this.api = api;
        this.configLoader = configLoader;
        this.rules = rules;

        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.weightx = 1.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel ruleInfoPanel = new JPanel(new GridBagLayout());
        ruleInfoPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        JLabel ruleLabel = new JLabel("Path:");
        JTextField pathTextField = new JTextField();
        pathTextField.setEditable(false);
        pathTextField.setText(configLoader.getRulesFilePath());
        JButton reloadButton = new JButton("Reload");
        JButton updateButton = new JButton("Update");
        ruleInfoPanel.add(ruleLabel);
        ruleInfoPanel.add(pathTextField, constraints);
        ruleInfoPanel.add(Box.createHorizontalStrut(5));
        ruleInfoPanel.add(reloadButton);
        ruleInfoPanel.add(Box.createHorizontalStrut(5));
        ruleInfoPanel.add(updateButton);

        reloadButton.addActionListener(this::reloadActionPerformed);
        updateButton.addActionListener(this::onlineUpdateActionPerformed);

        JPanel settingPanel = new JPanel(new BorderLayout());
        DefaultTableModel model = new DefaultTableModel();

        JTable table = new JTable(model);
        model.addColumn("Value");
        JScrollPane scrollPane = new JScrollPane(table);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setBorder(new EmptyBorder(0, 3, 0, 0));
        GridBagLayout layout = new GridBagLayout();
        layout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0};
        layout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        buttonPanel.setLayout(layout);

        JPanel inputPanel = new JPanel(new BorderLayout());
        JPanel inputPanelB = new JPanel(new BorderLayout());
        inputPanelB.setBorder(new EmptyBorder(0, 0, 3, 0));

        constraints.gridx = 1;
        JButton addButton = new JButton("Add");
        JButton removeButton = new JButton("Remove");
        JButton pasteButton = new JButton("Paste");
        JButton clearButton = new JButton("Clear");

        JComboBox<String> setTypeComboBox = new JComboBox<>();
        String[] mode = new String[]{"Exclude suffix", "Block host"};
        setTypeComboBox.setModel(new DefaultComboBoxModel<>(mode));
        setTypeComboBox.addActionListener(e -> {
            String selected = (String) setTypeComboBox.getSelectedItem();
            model.setRowCount(0);

            if (selected.equals("Exclude suffix")) {
                addDataToTable(configLoader.getExcludeSuffix().replaceAll("\\|", "\r\n"), model);
            }

            if (selected.equals("Block host")) {
                addDataToTable(configLoader.getBlockHost().replaceAll("\\|", "\r\n"), model);
            }
        });
        setTypeComboBox.setSelectedItem("Exclude suffix");

        model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                String selected = (String) setTypeComboBox.getSelectedItem();
                String values = getFirstColumnDataAsString(model);

                if (selected.equals("Exclude suffix")) {
                    if (!values.equals(configLoader.getExcludeSuffix()) && !values.isEmpty()) {
                        configLoader.setExcludeSuffix(values);
                    }
                }

                if (selected.equals("Block host")) {
                    if (!values.equals(configLoader.getExcludeSuffix()) && !values.isEmpty()) {
                        configLoader.setBlockHost(values);
                    }
                }
            }
        });

        constraints.insets = new Insets(0, 0, 3, 0);
        constraints.gridy = 0;
        buttonPanel.add(setTypeComboBox, constraints);
        constraints.gridy = 1;
        buttonPanel.add(addButton, constraints);
        constraints.gridy = 2;
        buttonPanel.add(removeButton, constraints);
        constraints.gridy = 3;
        buttonPanel.add(pasteButton, constraints);
        constraints.gridy = 4;
        buttonPanel.add(clearButton, constraints);

        JTextField addTextField = new JTextField();
        String defaultText = "Enter a new item";
        UIEnhancer.setTextFieldPlaceholder(addTextField, defaultText);

        inputPanelB.add(addTextField, BorderLayout.CENTER);
        inputPanel.add(scrollPane, BorderLayout.CENTER);
        inputPanel.add(inputPanelB, BorderLayout.NORTH);

        settingPanel.add(buttonPanel, BorderLayout.EAST);
        settingPanel.add(inputPanel, BorderLayout.CENTER);

        addButton.addActionListener(e -> {
            String addTextFieldText = addTextField.getText();
            if (!addTextFieldText.equals(defaultText)) {
                addDataToTable(addTextFieldText, model);
            }
            addTextField.setText("");
            addTextField.requestFocusInWindow();
        });

        pasteButton.addActionListener(e -> {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            try {
                String data = (String) clipboard.getData(DataFlavor.stringFlavor);

                if (data != null && !data.isEmpty()) {
                    addDataToTable(data, model);
                }
            } catch (Exception ignored) {
            }
        });

        removeButton.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow != -1) {
                model.removeRow(selectedRow);
            }
        });

        clearButton.addActionListener(e -> model.setRowCount(0));

        JPanel settingMainPanel = new JPanel(new BorderLayout());
        JLabel settingLabel = new JLabel("Setting:");
        JPanel settingLabelPanel = new JPanel(new BorderLayout());
        settingLabelPanel.add(settingLabel, BorderLayout.WEST);
        settingMainPanel.setBorder(new EmptyBorder(0, 5, 10, 5));
        settingMainPanel.add(settingLabelPanel, BorderLayout.NORTH);
        settingMainPanel.add(settingPanel, BorderLayout.CENTER);

        add(ruleInfoPanel, BorderLayout.NORTH);
        add(settingMainPanel, BorderLayout.CENTER);
    }

    private String getFirstColumnDataAsString(DefaultTableModel model) {
        StringBuilder firstColumnData = new StringBuilder();
        int numRows = model.getRowCount();

        for (int row = 0; row < numRows; row++) {
            firstColumnData.append(model.getValueAt(row, 0));
            if (row < numRows - 1) {
                firstColumnData.append("|");
            }
        }

        return firstColumnData.toString();
    }

    private void addDataToTable(String data, DefaultTableModel model) {
        if (!data.isBlank()) {
            String[] rows = data.split("\\r?\\n");
            for (String row : rows) {
                model.addRow(new String[]{row});
            }
            deduplicateTableData(model);
        }
    }

    private void deduplicateTableData(DefaultTableModel model) {
        // 使用 Map 存储每一行的数据，用于去重
        Set<List<Object>> rowData = new LinkedHashSet<>();

        int columnCount = model.getColumnCount();

        // 将每一行数据作为一个列表，添加到 Set 中
        for (int i = 0; i < model.getRowCount(); i++) {
            List<Object> row = new ArrayList<>();
            for (int j = 0; j < columnCount; j++) {
                row.add(model.getValueAt(i, j));
            }
            rowData.add(row);
        }

        // 清除原始数据
        model.setRowCount(0);

        // 将去重后的数据添加回去
        for (List<Object> uniqueRow : rowData) {
            model.addRow(uniqueRow.toArray());
        }
    }

    private void onlineUpdateActionPerformed(ActionEvent e) {
        // 添加提示框防止用户误触导致配置更新
        int retCode = JOptionPane.showConfirmDialog(null, "Do you want to update rules?", "Info", JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            configLoader.initRulesByNet();
            reloadActionPerformed(null);
        }
    }

    private void reloadActionPerformed(ActionEvent e) {
        rules.reloadRuleGroup();
    }
}
