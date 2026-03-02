package hae.component.rule;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import hae.service.ValidatorService;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.*;
import java.util.List;

public class Tester extends JPanel {

    private static final Gson GSON = new Gson();

    private final JTextField ruleNameField;
    private final JTextField commandField;
    private final JTextField timeoutField;
    private final JTextField bulkField;
    private final JTextField urlField;
    private final JTextField beforeField;
    private final JTextField afterField;
    private final JTextArea inputArea;
    private final DefaultTableModel resultModel;
    private final JTable resultTable;
    private final TableRowSorter<DefaultTableModel> sorter;
    private final JLabel statsLabel;
    private final JButton testButton;

    private String ruleName = "";
    private String firstRegex = "";
    private String groupName = "";

    public Tester() {
        ruleNameField = new JTextField();
        commandField = new JTextField();
        timeoutField = new JTextField("5000");
        bulkField = new JTextField("500");
        urlField = new JTextField();
        beforeField = new JTextField();
        afterField = new JTextField();
        inputArea = new JTextArea();
        resultModel = new DefaultTableModel(
                new String[]{"#", "Information", "Severity"},
                0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultTable = new JTable(resultModel);
        sorter = new TableRowSorter<>(resultModel);
        resultTable.setRowSorter(sorter);
        sorter.setComparator(0, (Comparator<Integer>) Integer::compareTo);
        sorter.setComparator(
                2,
                (Comparator<String>) ValidatorService::compareBySeverity
        );
        statsLabel = new JLabel(" ");
        testButton = new JButton("Test");

        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 10));

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JLabel titleLabel = new JLabel("Validator Tester");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        leftPanel.add(titleLabel);
        headerPanel.add(leftPanel, BorderLayout.WEST);

        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        JButton resetButton = new JButton("Reset");
        resetButton.addActionListener(e -> resetContent());
        rightPanel.add(resetButton);
        testButton.addActionListener(e -> runTest());
        rightPanel.add(testButton);
        headerPanel.add(rightPanel, BorderLayout.EAST);

        add(headerPanel, BorderLayout.NORTH);

        JPanel ruleInfoPanel = new JPanel(new GridBagLayout());
        ruleInfoPanel.setBorder(
                BorderFactory.createCompoundBorder(
                        BorderFactory.createEmptyBorder(0, 5, 0, 5),
                        BorderFactory.createTitledBorder("Rule")
                )
        );
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(2, 5, 2, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridy = 0;

        gbc.gridx = 0;
        gbc.weightx = 0;
        ruleInfoPanel.add(new JLabel("Name:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1;
        ruleNameField.setColumns(12);
        ruleInfoPanel.add(ruleNameField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        ruleInfoPanel.add(new JLabel("Command:"), gbc);
        gbc.gridx = 3;
        gbc.weightx = 2;
        commandField.setColumns(20);
        ruleInfoPanel.add(commandField, gbc);

        gbc.gridx = 4;
        gbc.weightx = 0;
        ruleInfoPanel.add(new JLabel("Timeout:"), gbc);
        gbc.gridx = 5;
        gbc.weightx = 0;
        timeoutField.setColumns(6);
        ruleInfoPanel.add(timeoutField, gbc);

        gbc.gridx = 6;
        gbc.weightx = 0;
        ruleInfoPanel.add(new JLabel("Bulk:"), gbc);
        gbc.gridx = 7;
        gbc.weightx = 0;
        bulkField.setColumns(5);
        ruleInfoPanel.add(bulkField, gbc);

        JPanel contextPanel = new JPanel(new GridBagLayout());
        contextPanel.setBorder(
                BorderFactory.createCompoundBorder(
                        BorderFactory.createEmptyBorder(0, 5, 0, 5),
                        BorderFactory.createTitledBorder("Context")
                )
        );
        GridBagConstraints cgbc = new GridBagConstraints();
        cgbc.insets = new Insets(2, 5, 2, 5);
        cgbc.fill = GridBagConstraints.HORIZONTAL;
        cgbc.gridy = 0;

        cgbc.gridx = 0;
        cgbc.weightx = 0;
        contextPanel.add(new JLabel("URL:"), cgbc);
        cgbc.gridx = 1;
        cgbc.weightx = 1;
        urlField.setColumns(12);
        contextPanel.add(urlField, cgbc);

        cgbc.gridx = 2;
        cgbc.weightx = 0;
        contextPanel.add(new JLabel("Before:"), cgbc);
        cgbc.gridx = 3;
        cgbc.weightx = 1;
        beforeField.setColumns(12);
        contextPanel.add(beforeField, cgbc);

        cgbc.gridx = 4;
        cgbc.weightx = 0;
        contextPanel.add(new JLabel("After:"), cgbc);
        cgbc.gridx = 5;
        cgbc.weightx = 1;
        afterField.setColumns(12);
        contextPanel.add(afterField, cgbc);

        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        topPanel.add(ruleInfoPanel);
        topPanel.add(contextPanel);

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(
                BorderFactory.createTitledBorder(
                        BorderFactory.createEtchedBorder(),
                        "Input",
                        TitledBorder.LEFT,
                        TitledBorder.TOP
                )
        );
        inputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        inputPanel.add(new JScrollPane(inputArea), BorderLayout.CENTER);

        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(
                BorderFactory.createTitledBorder(
                        BorderFactory.createEtchedBorder(),
                        "Output",
                        TitledBorder.LEFT,
                        TitledBorder.TOP
                )
        );

        resultTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        resultTable.getColumnModel().getColumn(0).setMaxWidth(100);
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        resultTable.getColumnModel().getColumn(2).setMaxWidth(100);
        resultTable
                .getColumnModel()
                .getColumn(2)
                .setCellRenderer(new ValidatorService.SeverityBadgeRenderer());
        outputPanel.add(new JScrollPane(resultTable), BorderLayout.CENTER);

        statsLabel.setBorder(BorderFactory.createEmptyBorder(3, 5, 3, 5));
        outputPanel.add(statsLabel, BorderLayout.SOUTH);

        JSplitPane contentSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                inputPanel,
                outputPanel
        );
        contentSplit.addComponentListener(
                new ComponentAdapter() {
                    @Override
                    public void componentResized(ComponentEvent e) {
                        contentSplit.setDividerLocation(0.4);
                    }
                }
        );

        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(topPanel, BorderLayout.NORTH);
        centerPanel.add(contentSplit, BorderLayout.CENTER);

        add(centerPanel, BorderLayout.CENTER);
    }

    public void setSelectedRuleFromTable(JTable ruleTable, String groupName) {
        int selectedRow = ruleTable.getSelectedRow();
        if (selectedRow < 0) return;

        DefaultTableModel model = (DefaultTableModel) ruleTable.getModel();
        int modelRow = ruleTable.convertRowIndexToModel(selectedRow);
        Vector<Object> rowData = (Vector<Object>) model
                .getDataVector()
                .get(modelRow);

        this.groupName = groupName;
        this.ruleName = String.valueOf(rowData.get(1));
        this.firstRegex = String.valueOf(rowData.get(2));

        String command = String.valueOf(rowData.get(9));

        int timeout = 5000;
        Object tObj = rowData.get(10);
        if (tObj instanceof Number) timeout = ((Number) tObj).intValue();
        else try {
            timeout = Integer.parseInt(tObj.toString().trim());
        } catch (NumberFormatException ignored) {
        }

        int bulk = 500;
        Object bObj = rowData.get(11);
        if (bObj instanceof Number) bulk = ((Number) bObj).intValue();
        else try {
            bulk = Integer.parseInt(bObj.toString().trim());
        } catch (NumberFormatException ignored) {
        }

        ruleNameField.setText(this.ruleName);
        commandField.setText(command);
        timeoutField.setText(String.valueOf(timeout));
        bulkField.setText(String.valueOf(bulk));
    }

    private void resetContent() {
        inputArea.setText("");
        resultModel.setRowCount(0);
        statsLabel.setText(" ");
    }

    private void runTest() {
        String command = commandField.getText().trim();
        if (command.isBlank()) {
            JOptionPane.showMessageDialog(
                    this,
                    "No validator command specified.",
                    "Info",
                    JOptionPane.INFORMATION_MESSAGE
            );
            return;
        }

        String inputText = inputArea.getText().trim();
        if (inputText.isEmpty()) {
            JOptionPane.showMessageDialog(
                    this,
                    "Please enter at least one test case.",
                    "Info",
                    JOptionPane.INFORMATION_MESSAGE
            );
            return;
        }

        String[] lines = inputText.split("\\r?\\n");
        List<String> matches = new ArrayList<>();
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) matches.add(trimmed);
        }
        if (matches.isEmpty()) return;

        String currentName = ruleNameField.getText().trim();
        if (!currentName.isEmpty()) this.ruleName = currentName;

        int timeout = 5000;
        try {
            timeout = Integer.parseInt(timeoutField.getText().trim());
        } catch (NumberFormatException ignored) {
        }
        int bulk = 500;
        try {
            bulk = Integer.parseInt(bulkField.getText().trim());
        } catch (NumberFormatException ignored) {
        }

        int finalTimeout = timeout;
        int finalBulk = Math.max(bulk, 1);
        String url = urlField.getText().trim();
        String before = beforeField.getText().trim();
        String after = afterField.getText().trim();

        resultModel.setRowCount(0);
        statsLabel.setText("Running...");
        // 先将焦点移到结果表格，再禁用按钮，避免焦点自动跳到输入框
        resultTable.requestFocusInWindow();
        testButton.setEnabled(false);

        new SwingWorker<TestResult, Void>() {
            @Override
            protected TestResult doInBackground() {
                long start = System.currentTimeMillis();
                Map<Integer, String> allResults = new HashMap<>();

                for (
                        int offset = 0;
                        offset < matches.size();
                        offset += finalBulk
                ) {
                    List<String> batch = matches.subList(
                            offset,
                            Math.min(offset + finalBulk, matches.size())
                    );
                    String inputJson = buildInputJson(
                            batch,
                            offset,
                            url,
                            before,
                            after
                    );
                    String output = ValidatorService.executeCommand(
                            command,
                            inputJson,
                            finalTimeout
                    );
                    if (output != null) {
                        allResults.putAll(ValidatorService.parseOutput(output));
                    } else {
                        for (int i = 0; i < batch.size(); i++) {
                            allResults.put(offset + i, "timeout");
                        }
                    }
                }

                long elapsed = System.currentTimeMillis() - start;
                return new TestResult(allResults, elapsed, matches);
            }

            @Override
            protected void done() {
                testButton.setEnabled(true);
                try {
                    displayResults(get());
                } catch (Exception e) {
                    statsLabel.setText("Error: " + e.getMessage());
                }
            }
        }
                .execute();
    }

    private String buildInputJson(
            List<String> matches,
            int indexOffset,
            String url,
            String before,
            String after
    ) {
        JsonObject root = new JsonObject();

        JsonObject ruleObj = new JsonObject();
        ruleObj.addProperty("name", ruleName);
        ruleObj.addProperty("regex", firstRegex);
        ruleObj.addProperty("group", groupName);
        root.add("rule", ruleObj);

        JsonArray items = new JsonArray();
        for (int i = 0; i < matches.size(); i++) {
            JsonObject item = new JsonObject();
            item.addProperty("index", indexOffset + i);

            JsonObject data = new JsonObject();
            data.addProperty("match", matches.get(i));
            data.addProperty("url", url);
            JsonObject context = new JsonObject();
            context.addProperty("before", before);
            context.addProperty("after", after);
            data.add("context", context);

            item.add("data", data);
            items.add(item);
        }
        root.add("items", items);

        return GSON.toJson(root);
    }

    private void displayResults(TestResult result) {
        resultModel.setRowCount(0);

        int highCount = 0,
                mediumCount = 0,
                lowCount = 0,
                noneCount = 0;
        boolean hasTimeout = false;
        for (int i = 0; i < result.matches.size(); i++) {
            String severity = result.severityMap.getOrDefault(
                    i,
                    ValidatorService.SEVERITY_NONE
            );
            resultModel.addRow(
                    new Object[]{i + 1, result.matches.get(i), severity}
            );
            switch (severity) {
                case ValidatorService.SEVERITY_HIGH -> highCount++;
                case ValidatorService.SEVERITY_MEDIUM -> mediumCount++;
                case ValidatorService.SEVERITY_LOW -> lowCount++;
                case "timeout" -> hasTimeout = true;
                default -> noneCount++;
            }
        }

        String stats = String.format(
                "Elapsed: %dms | Items: %d | High: %d, Medium: %d, Low: %d, None: %d",
                result.elapsed,
                result.matches.size(),
                highCount,
                mediumCount,
                lowCount,
                noneCount
        );
        if (hasTimeout) stats += " (some batches timed out)";
        statsLabel.setText(stats);

        sorter.setSortKeys(
                List.of(new RowSorter.SortKey(2, SortOrder.ASCENDING))
        );
    }

    private record TestResult(
            Map<Integer, String> severityMap,
            long elapsed,
            List<String> matches
    ) {
    }
}
