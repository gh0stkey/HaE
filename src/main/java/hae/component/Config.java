package hae.component;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import hae.component.board.message.MessageTableModel;
import hae.component.rule.Rules;
import hae.instances.http.HttpMessageActiveHandler;
import hae.instances.http.HttpMessagePassiveHandler;
import hae.utils.ConfigLoader;
import hae.utils.UIEnhancer;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.event.*;
import java.util.List;
import java.util.*;

public class Config extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final MessageTableModel messageTableModel;
    private final Rules rules;

    private Registration activeHandler;
    private Registration passiveHandler;

    public Config(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel, Rules rules) {
        this.api = api;
        this.configLoader = configLoader;
        this.messageTableModel = messageTableModel;
        this.rules = rules;

        this.activeHandler = api.http().registerHttpHandler(new HttpMessageActiveHandler(api, configLoader, messageTableModel));
        this.passiveHandler = api.scanner().registerScanCheck(new HttpMessagePassiveHandler(api, configLoader, messageTableModel));

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
        JButton reinitButton = new JButton("Reinit");
        ruleInfoPanel.add(ruleLabel);
        ruleInfoPanel.add(pathTextField, constraints);
        ruleInfoPanel.add(Box.createHorizontalStrut(5));
        ruleInfoPanel.add(reinitButton);
        ruleInfoPanel.add(Box.createHorizontalStrut(5));
        ruleInfoPanel.add(reloadButton);

        reloadButton.addActionListener(this::reloadActionPerformed);
        reinitButton.addActionListener(this::reinitActionPerformed);

        constraints.gridx = 1;
        JTabbedPane configTabbedPanel = new JTabbedPane();

        String[] settingMode = new String[]{"Exclude suffix", "Block host", "Exclude status"};
        JPanel settingPanel = createConfigTablePanel(settingMode);

        JPanel northPanel = new JPanel(new BorderLayout());

        JPanel modePanel = getModePanel();
        JScrollPane modeScrollPane = new JScrollPane(modePanel);
        modeScrollPane.setBorder(new TitledBorder("Mode"));

        JTextField limitPanel = getLimitPanel();
        JScrollPane limitScrollPane = new JScrollPane(limitPanel);
        limitScrollPane.setBorder(new TitledBorder("Limit Size (MB)"));

        JSplitPane northTopPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, modeScrollPane, limitScrollPane);
        northTopPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                northTopPanel.setDividerLocation(0.5);
            }
        });

        JPanel scopePanel = getScopePanel();
        JScrollPane scopeScrollPane = new JScrollPane(scopePanel);
        scopeScrollPane.setBorder(new TitledBorder("Scope"));

        northPanel.add(scopeScrollPane, BorderLayout.SOUTH);
        northPanel.add(northTopPanel, BorderLayout.NORTH);
        settingPanel.add(northPanel, BorderLayout.NORTH);

        configTabbedPanel.add("Setting", settingPanel);
        add(ruleInfoPanel, BorderLayout.NORTH);
        add(configTabbedPanel, BorderLayout.CENTER);
    }

    private JPanel getScopePanel() {
        JPanel scopePanel = new JPanel();
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.X_AXIS));
        scopePanel.setBorder(new EmptyBorder(3, 0, 6, 0));

        String[] scopeInit = hae.Config.scopeOptions.split("\\|");
        String[] scopeMode = configLoader.getScope().split("\\|");
        for (String scope : scopeInit) {
            JCheckBox checkBox = new JCheckBox(scope);
            scopePanel.add(checkBox);
            checkBox.addActionListener(e -> updateScope(checkBox));
            for (String mode : scopeMode) {
                if (scope.equals(mode)) {
                    checkBox.setSelected(true);
                }
            }
            updateScope(checkBox);
        }

        return scopePanel;
    }

    private JPanel getModePanel() {
        JPanel modePanel = new JPanel();
        modePanel.setLayout(new BoxLayout(modePanel, BoxLayout.X_AXIS));

        JCheckBox checkBox = new JCheckBox("Enable active http message handler");
        checkBox.setEnabled(hae.Config.proVersionStatus);
        modePanel.add(checkBox);
        checkBox.addActionListener(e -> updateModeStatus(checkBox));
        checkBox.setSelected(configLoader.getMode());
        updateModeStatus(checkBox);

        return modePanel;
    }

    private JTextField getLimitPanel() {
        JTextField limitSizeTextField = new JTextField();
        limitSizeTextField.getDocument().addDocumentListener(new DocumentListener() {
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
                String limitSizeText = limitSizeTextField.getText();
                configLoader.setLimitSize(limitSizeText);
            }
        });

        limitSizeTextField.setText(configLoader.getLimitSize());

        return limitSizeTextField;
    }

    private TableModelListener craeteSettingTableModelListener(JComboBox<String> setTypeComboBox, DefaultTableModel model) {
        return e -> {
            String selected = (String) setTypeComboBox.getSelectedItem();
            String values = getFirstColumnDataAsString(model);
            if (selected != null) {
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
            }
        };
    }

    private ActionListener createSettingActionListener(JComboBox<String> setTypeComboBox, DefaultTableModel model) {
        return e -> {
            String selected = (String) setTypeComboBox.getSelectedItem();
            model.setRowCount(0);
            if (selected != null) {
                if (selected.equals("Exclude suffix")) {
                    addDataToTable(configLoader.getExcludeSuffix().replaceAll("\\|", "\r\n"), model);
                }

                if (selected.equals("Block host")) {
                    addDataToTable(configLoader.getBlockHost().replaceAll("\\|", "\r\n"), model);
                }

                if (selected.equals("Exclude status")) {
                    addDataToTable(configLoader.getExcludeStatus().replaceAll("\\|", "\r\n"), model);
                }
            }
        };
    }


    private JPanel createConfigTablePanel(String[] mode) {
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

        model.addTableModelListener(craeteSettingTableModelListener(setTypeComboBox, model));

        setTypeComboBox.addActionListener(createSettingActionListener(setTypeComboBox, model));

        setTypeComboBox.setSelectedItem(mode[0]);

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


        addButton.addActionListener(e -> addActionPerformed(e, model, addTextField));

        addTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    addActionPerformed(null, model, addTextField);
                }
            }
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
        settingMainPanel.setBorder(new EmptyBorder(5, 15, 10, 15));
        JScrollPane settingScroller = new JScrollPane(settingPanel);
        settingScroller.setBorder(new TitledBorder("Setting"));
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

    public void updateModeStatus(JCheckBox checkBox) {
        boolean selected = checkBox.isSelected();
        configLoader.setMode(selected ? "true" : "false");

        if (checkBox.isSelected()) {
            if (hae.Config.proVersionStatus && passiveHandler.isRegistered()) {
                passiveHandler.deregister();
            }

            if (!activeHandler.isRegistered()) {
                activeHandler = api.http().registerHttpHandler(new HttpMessageActiveHandler(api, configLoader, messageTableModel));
            }
        } else {
            if (hae.Config.proVersionStatus && !passiveHandler.isRegistered()) {
                passiveHandler = api.scanner().registerScanCheck(new HttpMessagePassiveHandler(api, configLoader, messageTableModel));
            }

            if (activeHandler.isRegistered()) {
                activeHandler.deregister();
            }
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

    private void addActionPerformed(ActionEvent e, DefaultTableModel model, JTextField addTextField) {
        String addTextFieldText = addTextField.getText();
        if (addTextField.getForeground().equals(Color.BLACK)) {
            addDataToTable(addTextFieldText, model);
            addTextField.setText("");
            addTextField.requestFocusInWindow();
        }
    }

    private void reloadActionPerformed(ActionEvent e) {
        rules.reloadRuleGroup();
    }

    private void reinitActionPerformed(ActionEvent e) {
        int retCode = JOptionPane.showConfirmDialog(this, "Do you want to reinitialize rules? This action will overwrite your existing rules.", "Info", JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            boolean ret = configLoader.initRules();
            if (ret) {
                rules.reloadRuleGroup();
            }
        }
    }
}
