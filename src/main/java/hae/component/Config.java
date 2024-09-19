package hae.component;

import burp.api.montoya.MontoyaApi;
import hae.component.rule.Rules;
import hae.utils.ConfigLoader;
import hae.utils.UIEnhancer;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.*;

public class Config extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final Rules rules;
    private final String defaultText = "Enter a new item";

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
        ruleInfoPanel.setBorder(new EmptyBorder(10, 15, 5, 15));

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

        constraints.gridx = 1;
        JTabbedPane configTabbedPanel = new JTabbedPane();

        String[] settingMode = new String[]{"Exclude suffix", "Block host", "Exclude status", "Limit size (MB)"};
        JPanel settingPanel = createConfigTablePanel(settingMode, "Setting");
        JPanel scopePanel = getScopePanel();
        JScrollPane scopeScrollPane = new JScrollPane(scopePanel);
        scopeScrollPane.setBorder(new TitledBorder("Scope"));
        settingPanel.add(scopeScrollPane, BorderLayout.NORTH);
        configTabbedPanel.add("Setting", settingPanel);

        String[] aiMode = new String[]{"Alibaba", "Moonshot"};
        JPanel aiPanel = createConfigTablePanel(aiMode, "AI+");
        JTextArea promptTextArea = new JTextArea();
        promptTextArea.setLineWrap(true);
        promptTextArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                onTextChange();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                onTextChange();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                onTextChange();
            }

            private void onTextChange() {
                String promptText = promptTextArea.getText();
                configLoader.setAIPrompt(promptText);
            }
        });
        promptTextArea.setText(configLoader.getAIPrompt());
        JScrollPane promptScrollPane = new JScrollPane(promptTextArea);
        promptScrollPane.setBorder(new TitledBorder("Prompt"));
        promptScrollPane.setPreferredSize(new Dimension(0, 100));
        aiPanel.add(promptScrollPane, BorderLayout.NORTH);
        configTabbedPanel.add("AI+", aiPanel);
        add(ruleInfoPanel, BorderLayout.NORTH);
        add(configTabbedPanel, BorderLayout.CENTER);
    }

    private JPanel getScopePanel() {
        JPanel scopePanel = new JPanel();
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.X_AXIS));

        String[] scopeInit = hae.Config.scopeOptions.split("\\|");
        String[] scopeMode = configLoader.getScope().split("\\|");
        for (String scope : scopeInit) {
            JCheckBox checkBox = new JCheckBox(scope);
            scopePanel.add(checkBox);
            for (String mode : scopeMode) {
                if (scope.equals(mode)) {
                    checkBox.setSelected(true);
                }
            }

            checkBox.addActionListener(e -> updateScope(checkBox));
        }
        return scopePanel;
    }

    private TableModelListener craeteSettingTableModelListener(JComboBox<String> setTypeComboBox, DefaultTableModel model) {
        return new TableModelListener() {
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
                    if (!values.equals(configLoader.getBlockHost()) && !values.isEmpty()) {
                        configLoader.setBlockHost(values);
                    }
                }

                if (selected.equals("Exclude status")) {
                    if (!values.equals(configLoader.getExcludeStatus()) && !values.isEmpty()) {
                        configLoader.setExcludeStatus(values);
                    }
                }

                if (selected.contains("Limit size")) {
                    if (!values.equals(configLoader.getExcludeStatus()) && !values.isEmpty()) {
                        String[] limit = values.split("\\|");
                        configLoader.setLimitSize(limit[limit.length - 1]);
                    }
                }
            }
        };
    }

    private ActionListener createSettingActionListener(JComboBox<String> setTypeComboBox, DefaultTableModel model) {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selected = (String) setTypeComboBox.getSelectedItem();
                model.setRowCount(0);

                if (selected.equals("Exclude suffix")) {
                    addDataToTable(configLoader.getExcludeSuffix().replaceAll("\\|", "\r\n"), model);
                }

                if (selected.equals("Block host")) {
                    addDataToTable(configLoader.getBlockHost().replaceAll("\\|", "\r\n"), model);
                }

                if (selected.equals("Exclude status")) {
                    addDataToTable(configLoader.getExcludeStatus().replaceAll("\\|", "\r\n"), model);
                }

                if (selected.contains("Limit size")) {
                    addDataToTable(configLoader.getLimitSize(), model);
                }
            }
        };
    }

    private TableModelListener craeteAITableModelListener(JComboBox<String> setTypeComboBox, DefaultTableModel model) {
        return new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
                String selected = (String) setTypeComboBox.getSelectedItem();
                String values = getFirstColumnDataAsString(model);

                if (selected.equals("Alibaba")) {
                    if (!values.equals(configLoader.getAlibabaAIAPIKey()) && !values.isEmpty()) {
                        configLoader.setAlibabaAIAPIKey(values);
                    }
                }

                if (selected.equals("Moonshot")) {
                    if (!values.equals(configLoader.getMoonshotAIAPIKey()) && !values.isEmpty()) {
                        configLoader.setMoonshotAIAPIKey(values);
                    }
                }
            }
        };
    }

    private ActionListener createAIActionListener(JComboBox<String> setTypeComboBox, DefaultTableModel model) {
        return new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selected = (String) setTypeComboBox.getSelectedItem();
                model.setRowCount(0);

                if (selected.equals("Alibaba")) {
                    addDataToTable(configLoader.getAlibabaAIAPIKey().replaceAll("\\|", "\r\n"), model);
                }

                if (selected.equals("Moonshot")) {
                    addDataToTable(configLoader.getMoonshotAIAPIKey().replaceAll("\\|", "\r\n"), model);
                }
            }
        };
    }

    private JPanel createConfigTablePanel(String[] mode, String type) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.weightx = 1.0;
        constraints.fill = GridBagConstraints.HORIZONTAL;

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

        JButton addButton = new JButton("Add");
        JButton removeButton = new JButton("Remove");
        JButton pasteButton = new JButton("Paste");
        JButton clearButton = new JButton("Clear");

        JComboBox<String> setTypeComboBox = new JComboBox<>();
        setTypeComboBox.setModel(new DefaultComboBoxModel<>(mode));

        setTypeComboBox.addActionListener(type.equals("AI+") ? createAIActionListener(setTypeComboBox, model) : createSettingActionListener(setTypeComboBox, model));

        setTypeComboBox.setSelectedItem(mode[0]);

        model.addTableModelListener(type.equals("AI+") ? craeteAITableModelListener(setTypeComboBox, model) : craeteSettingTableModelListener(setTypeComboBox, model));

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
        UIEnhancer.setTextFieldPlaceholder(addTextField, defaultText);

        inputPanelB.add(addTextField, BorderLayout.CENTER);
        inputPanel.add(scrollPane, BorderLayout.CENTER);
        inputPanel.add(inputPanelB, BorderLayout.NORTH);

        settingPanel.add(buttonPanel, BorderLayout.EAST);
        settingPanel.add(inputPanel, BorderLayout.CENTER);


        addButton.addActionListener(e -> addActionPerformed(e, model, addTextField, setTypeComboBox.getSelectedItem().toString()));

        addTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    addActionPerformed(null, model, addTextField, setTypeComboBox.getSelectedItem().toString());
                }
            }
        });

        pasteButton.addActionListener(e -> {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            try {
                String data = (String) clipboard.getData(DataFlavor.stringFlavor);
                if (setTypeComboBox.getSelectedItem().toString().contains("Limit size")) {
                    model.setRowCount(0);
                }
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
        settingMainPanel.setBorder(new EmptyBorder(5, 15, 10, 15));
        JScrollPane settingScroller = new JScrollPane(settingPanel);
        settingScroller.setBorder(new TitledBorder(type.equals("AI+") ? "API Key" : "Setting"));
        settingMainPanel.add(settingScroller, BorderLayout.CENTER);

        return settingMainPanel;
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

    public void updateScope(JCheckBox checkBox) {
        String boxText = checkBox.getText();
        boolean selected = checkBox.isSelected();

        Set<String> HaEScope = new HashSet<>(Arrays.asList(configLoader.getScope().split("\\|")));

        if (selected) {
            HaEScope.add(boxText);
        } else {
            HaEScope.remove(boxText);
        }

        configLoader.setScope(String.join("|", HaEScope));
    }

    private void addActionPerformed(ActionEvent e, DefaultTableModel model, JTextField addTextField, String comboBoxSelected) {
        String addTextFieldText = addTextField.getText();
        if (addTextField.getForeground().equals(Color.BLACK)) {
            if (comboBoxSelected.contains("Limit size")) {
                model.setRowCount(0);
            }
            addDataToTable(addTextFieldText, model);
            addTextField.setText("");
            addTextField.requestFocusInWindow();
        }
    }

    private void onlineUpdateActionPerformed(ActionEvent e) {
        // 添加提示框防止用户误触导致配置更新
        int retCode = JOptionPane.showConfirmDialog(this, "Do you want to update rules?", "Info", JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            configLoader.initRulesByNet();
            reloadActionPerformed(null);
        }
    }

    private void reloadActionPerformed(ActionEvent e) {
        rules.reloadRuleGroup();
    }
}
