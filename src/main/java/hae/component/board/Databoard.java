package hae.component.board;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import hae.component.board.message.MessageEntry;
import hae.component.board.message.MessageTableModel;
import hae.component.board.message.MessageTableModel.MessageTable;
import hae.instances.http.utils.RegularMatcher;
import hae.utils.ConfigLoader;
import hae.utils.project.ProjectProcessor;
import hae.utils.project.model.HaeFileContent;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.List;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class Databoard extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final ProjectProcessor projectProcessor;
    private final MessageTableModel messageTableModel;

    private JTextField hostTextField;
    private JTabbedPane dataTabbedPane;
    private JSplitPane splitPane;
    private MessageTable messageTable;
    private JProgressBar progressBar;

    private static Boolean isMatchHost = false;
    private final DefaultComboBoxModel comboBoxModel = new DefaultComboBoxModel();
    private final JComboBox hostComboBox = new JComboBox(comboBoxModel);

    private SwingWorker<Boolean, Void> currentWorker;

    public Databoard(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel) {
        this.api = api;
        this.configLoader = configLoader;
        this.projectProcessor = new ProjectProcessor(api);
        this.messageTableModel = messageTableModel;

        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        ((GridBagLayout) getLayout()).columnWidths = new int[]{25, 0, 0, 0, 20, 0};
        ((GridBagLayout) getLayout()).rowHeights = new int[]{0, 65, 20, 25, 0};
        ((GridBagLayout) getLayout()).columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, 0.0, 1.0E-4};
        ((GridBagLayout) getLayout()).rowWeights = new double[]{0.0, 1.0, 0.0, 0.0, 1.0E-4};

        JLabel hostLabel = new JLabel("Host:");

        JButton clearButton = new JButton("Clear");
        JButton exportButton = new JButton("Export");
        JButton importButton = new JButton("Import");
        JButton actionButton = new JButton("Action");
        JPanel menuPanel = new JPanel(new GridLayout(3, 1, 0, 5));
        menuPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JPopupMenu menu = new JPopupMenu();
        menuPanel.add(clearButton);
        menuPanel.add(exportButton);
        menuPanel.add(importButton);
        menu.add(menuPanel);

        hostTextField = new JTextField();
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);

        dataTabbedPane.setPreferredSize(new Dimension(500, 0));
        dataTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        splitPane.setLeftComponent(dataTabbedPane);

        actionButton.addActionListener(e -> {
            int x = 0;
            int y = actionButton.getHeight();
            menu.show(actionButton, x, y);
        });

        clearButton.addActionListener(this::clearActionPerformed);
        exportButton.addActionListener(this::exportActionPerformed);
        importButton.addActionListener(this::importActionPerformed);

        progressBar = new JProgressBar();

        splitPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                resizePanel();
            }
        });

        splitPane.setVisible(false);
        progressBar.setVisible(false);

        add(hostLabel, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(hostTextField, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(actionButton, new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        add(splitPane, new GridBagConstraints(1, 1, 3, 1, 0.0, 1.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 5, 0, 5), 0, 0));
        add(progressBar, new GridBagConstraints(1, 3, 3, 1, 1.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.HORIZONTAL,
                new Insets(0, 5, 0, 5), 0, 0));
        hostComboBox.setMaximumRowCount(5);
        add(hostComboBox, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        setAutoMatch();
    }

    private void resizePanel() {
        splitPane.setDividerLocation(0.4);
        TableColumnModel columnModel = messageTable.getColumnModel();
        int totalWidth = (int) (getWidth() * 0.6);
        columnModel.getColumn(0).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(1).setPreferredWidth((int) (totalWidth * 0.3));
        columnModel.getColumn(2).setPreferredWidth((int) (totalWidth * 0.3));
        columnModel.getColumn(3).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(4).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(5).setPreferredWidth((int) (totalWidth * 0.1));
    }

    private void setProgressBar(boolean status) {
        progressBar.setIndeterminate(status);
        if (!status) {
            progressBar.setMaximum(100);
            progressBar.setString("OK");
            progressBar.setStringPainted(true);
            progressBar.setValue(progressBar.getMaximum());
        } else {
            progressBar.setString("Loading...");
            progressBar.setStringPainted(true);
        }
    }

    private void setAutoMatch() {
        hostComboBox.setSelectedItem(null);
        hostComboBox.addActionListener(this::handleComboBoxAction);

        hostTextField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                handleKeyEvents(e);
            }
        });

        hostTextField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                filterComboBoxList();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                filterComboBoxList();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                filterComboBoxList();
            }

        });
    }

    private void handleComboBoxAction(ActionEvent e) {
        if (!isMatchHost && hostComboBox.getSelectedItem() != null) {
            progressBar.setVisible(true);
            setProgressBar(true);
            String selectedHost = hostComboBox.getSelectedItem().toString();
            hostTextField.setText(selectedHost);

            if (currentWorker != null && !currentWorker.isDone()) {
                currentWorker.cancel(true);
            }

            currentWorker = new SwingWorker<Boolean, Void>() {
                @Override
                protected Boolean doInBackground() {
                    return populateTabbedPaneByHost(selectedHost);
                }

                @Override
                protected void done() {
                    if (!isCancelled()) {
                        try {
                            boolean status = get();
                            if (status) {
                                JSplitPane messageSplitPane = messageTableModel.getSplitPane();
                                splitPane.setRightComponent(messageSplitPane);
                                messageTable = messageTableModel.getMessageTable();
                                resizePanel();

                                splitPane.setVisible(true);
                                hostTextField.setText(selectedHost);

                                hostComboBox.setPopupVisible(false);
                                applyHostFilter(selectedHost);
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            };

            currentWorker.execute();
        }
    }

    private void handleKeyEvents(KeyEvent e) {
        isMatchHost = true;
        int keyCode = e.getKeyCode();

        if (keyCode == KeyEvent.VK_SPACE && hostComboBox.isPopupVisible()) {
            e.setKeyCode(KeyEvent.VK_ENTER);
        }

        if (Arrays.asList(KeyEvent.VK_DOWN, KeyEvent.VK_UP).contains(keyCode)) {
            hostComboBox.dispatchEvent(e);
        }

        if (keyCode == KeyEvent.VK_ENTER) {
            isMatchHost = false;
            handleComboBoxAction(null);
        }

        if (keyCode == KeyEvent.VK_ESCAPE) {
            hostComboBox.setPopupVisible(false);
        }

        isMatchHost = false;
    }

    private boolean populateTabbedPaneByHost(String selectedHost) {
        ConcurrentHashMap<String, Map<String, List<String>>> dataMap = Config.globalDataMap;
        Map<String, List<String>> selectedDataMap;

        if (selectedHost.contains("*")) {
            selectedDataMap = new HashMap<>();
            dataMap.keySet().parallelStream().forEach(key -> {
                if ((StringProcessor.matchesHostPattern(key, selectedHost) || selectedHost.equals("*")) && !key.contains("*")) {
                    Map<String, List<String>> ruleMap = dataMap.get(key);
                    for (String ruleKey : ruleMap.keySet()) {
                        List<String> dataList = ruleMap.get(ruleKey);
                        if (selectedDataMap.containsKey(ruleKey)) {
                            List<String> mergedList = new ArrayList<>(selectedDataMap.get(ruleKey));
                            mergedList.addAll(dataList);
                            HashSet<String> uniqueSet = new HashSet<>(mergedList);
                            selectedDataMap.put(ruleKey, new ArrayList<>(uniqueSet));
                        } else {
                            selectedDataMap.put(ruleKey, dataList);
                        }
                    }
                }
            });
        } else {
            selectedDataMap = dataMap.get(selectedHost);
        }

        if (!selectedDataMap.isEmpty()) {
            dataTabbedPane.removeAll();

            for (Map.Entry<String, List<String>> entry : selectedDataMap.entrySet()) {
                String tabTitle = String.format("%s (%s)", entry.getKey(), entry.getValue().size());
                Datatable datatablePanel = new Datatable(api, entry.getKey(), entry.getValue());
                datatablePanel.setTableListener(messageTableModel);
                dataTabbedPane.addTab(tabTitle, datatablePanel);
            }

            return true;
        }
        return false;
    }

    private void filterComboBoxList() {
        isMatchHost = true;
        comboBoxModel.removeAllElements();
        String input = hostTextField.getText().toLowerCase();

        if (!input.isEmpty()) {
            for (String host : getHostByList()) {
                String lowerCaseHost = host.toLowerCase();
                if (lowerCaseHost.contains(input)) {
                    if (lowerCaseHost.equals(input)) {
                        comboBoxModel.insertElementAt(lowerCaseHost, 0);
                        comboBoxModel.setSelectedItem(lowerCaseHost);
                    } else {
                        comboBoxModel.addElement(host);
                    }
                }
            }
        }

        hostComboBox.setPopupVisible(comboBoxModel.getSize() > 0);
        isMatchHost = false;
    }

    private void applyHostFilter(String filterText) {
        TableRowSorter<TableModel> sorter = (TableRowSorter<TableModel>) messageTable.getRowSorter();
        String cleanedText = StringProcessor.replaceFirstOccurrence(filterText, "*.", "");

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                RowFilter<Object, Object> rowFilter = new RowFilter<Object, Object>() {
                    public boolean include(Entry<?, ?> entry) {
                        if (cleanedText.equals("*")) {
                            return true;
                        } else {
                            String host = StringProcessor.getHostByUrl((String) entry.getValue(1));
                            return StringProcessor.matchesHostPattern(host, filterText);
                        }
                    }
                };

                sorter.setRowFilter(rowFilter);
                messageTableModel.applyHostFilter(filterText);

                return null;
            }

            @Override
            protected void done() {
                setProgressBar(false);
            }
        }.execute();

    }

    private List<String> getHostByList() {
        if (!Config.globalDataMap.keySet().isEmpty()) {
            return new ArrayList<>(Config.globalDataMap.keySet());
        }
        return new ArrayList<>();
    }

    private void exportActionPerformed(ActionEvent e) {
        String selectedHost = hostTextField.getText().trim();

        if (selectedHost.isEmpty()) {
            return;
        }

        String exportDir = selectDirectory(true);

        if (exportDir.isEmpty()) {
            return;
        }

        new SwingWorker<List<String>, Void>() {
            @Override
            protected List<String> doInBackground() {
                ConcurrentHashMap<String, Map<String, List<String>>> dataMap = Config.globalDataMap;
                return exportData(selectedHost, exportDir, dataMap);
            }

            @Override
            protected void done() {
                try {
                    List<String> taskStatusList = get();
                    if (!taskStatusList.isEmpty()) {
                        String exportStatusMessage = String.format("Exported File List Status:\n%s", String.join("\n", taskStatusList));
                        JOptionPane.showConfirmDialog(Databoard.this, exportStatusMessage, "Info", JOptionPane.YES_OPTION);
                    }
                } catch (Exception ignored) {
                }
            }
        }.execute();
    }

    private List<String> exportData(String selectedHost, String exportDir, Map<String, Map<String, List<String>>> dataMap) {
        return dataMap.entrySet().stream()
                .filter(entry -> selectedHost.equals("*") || StringProcessor.matchesHostPattern(entry.getKey(), selectedHost))
                .filter(entry -> !entry.getKey().contains("*"))
                .map(entry -> exportEntry(entry, exportDir))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private String exportEntry(Map.Entry<String, Map<String, List<String>>> entry, String exportDir) {
        String key = entry.getKey();
        Map<String, List<String>> ruleMap = entry.getValue();

        if (ruleMap == null || ruleMap.isEmpty()) {
            return null;
        }

        List<MessageEntry> messageEntryList = messageTableModel.getLogs();

        Map<MessageEntry, String> entryUUIDMap = messageEntryList.stream()
                .collect(Collectors.toMap(
                        messageEntry -> messageEntry,
                        messageEntry -> StringProcessor.getRandomUUID(),
                        (existing, replacement) -> existing // 在冲突时保留现有的映射
                ));

        Map<String, Map<String, Object>> httpMap = processEntries(
                messageEntryList,
                key,
                entryUUIDMap,
                this::createHttpItemMap
        );

        Map<String, Map<String, Object>> urlMap = processEntries(
                messageEntryList,
                key,
                entryUUIDMap,
                this::creteUrlItemMap
        );

        String hostName = key.replace(":", "_");
        String filename = String.format("%s/%s-%s.hae", exportDir, StringProcessor.getCurrentTime(), hostName);
        boolean createdStatus = projectProcessor.createHaeFile(filename, key, ruleMap, urlMap, httpMap);

        return String.format("Filename: %s, Status: %s", filename, createdStatus);
    }


    private Map<String, Map<String, Object>> processEntries(List<MessageEntry> messageEntryList, String key, Map<MessageEntry, String> entryUUIDMap, Function<MessageEntry, Map<String, Object>> mapFunction) {
        return messageEntryList.stream()
                .filter(messageEntry -> !StringProcessor.getHostByUrl(messageEntry.getUrl()).isEmpty())
                .filter(messageEntry -> StringProcessor.getHostByUrl(messageEntry.getUrl()).equals(key))
                .collect(Collectors.toMap(
                        entryUUIDMap::get,
                        mapFunction,
                        (existing, replacement) -> existing
                ));
    }

    private Map<String, Object> creteUrlItemMap(MessageEntry entry) {
        Map<String, Object> urlItemMap = new LinkedHashMap<>();
        urlItemMap.put("url", entry.getUrl());
        urlItemMap.put("method", entry.getMethod());
        urlItemMap.put("status", entry.getStatus());
        urlItemMap.put("length", entry.getLength());
        urlItemMap.put("comment", entry.getComment());
        urlItemMap.put("color", entry.getColor());
        urlItemMap.put("size", String.valueOf(entry.getRequestResponse().request().toByteArray().length()));
        return urlItemMap;
    }

    private Map<String, Object> createHttpItemMap(MessageEntry entry) {
        Map<String, Object> httpItemMap = new LinkedHashMap<>();
        httpItemMap.put("request", entry.getRequestResponse().request().toByteArray().getBytes());
        httpItemMap.put("response", entry.getRequestResponse().response().toByteArray().getBytes());
        return httpItemMap;
    }

    private void importActionPerformed(ActionEvent e) {
        String exportDir = selectDirectory(false);
        if (exportDir.isEmpty()) {
            return;
        }

        new SwingWorker<List<String>, Void>() {
            @Override
            protected List<String> doInBackground() {
                List<String> filesWithExtension = findFilesWithExtension(new File(exportDir), ".hae");
                return filesWithExtension.stream()
                        .map(Databoard.this::importData)
                        .collect(Collectors.toList());
            }

            @Override
            protected void done() {
                try {
                    List<String> taskStatusList = get();
                    if (!taskStatusList.isEmpty()) {
                        String importStatusMessage = "Imported File List Status:\n" + String.join("\n", taskStatusList);
                        JOptionPane.showConfirmDialog(Databoard.this, importStatusMessage, "Info", JOptionPane.YES_OPTION);
                    }
                } catch (Exception ignored) {
                }
            }
        }.execute();
    }

    private String importData(String filename) {
        HaeFileContent haeFileContent = projectProcessor.readHaeFile(filename);
        boolean readStatus = haeFileContent != null;

        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
        List<Future<?>> futures = new ArrayList<>();

        if (readStatus) {
            try {
                String host = haeFileContent.getHost();
                haeFileContent.getDataMap().forEach((key, value) -> RegularMatcher.putDataToGlobalMap(host, key, value));

                haeFileContent.getUrlMap().forEach((key, urlItemMap) -> {
                    Future<?> future = executor.submit(() -> {
                        String url = urlItemMap.get("url");
                        String comment = urlItemMap.get("comment");
                        String color = urlItemMap.get("color");
                        String length = urlItemMap.get("length");
                        String method = urlItemMap.get("method");
                        String status = urlItemMap.get("status");
                        String path = haeFileContent.getHttpPath();

                        messageTableModel.add(null, url, method, status, length, comment, color, key, path);
                    });

                    futures.add(future);
                });

                for (Future<?> future : futures) {
                    try {
                        future.get();
                    } catch (InterruptedException | ExecutionException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("importData: " + e.getMessage());
            } finally {
                executor.shutdown();
            }
        }

        return String.format("Filename: %s, Status: %s", filename, readStatus);
    }

    private List<String> findFilesWithExtension(File directory, String extension) {
        List<String> filePaths = new ArrayList<>();
        if (directory.isDirectory()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        filePaths.addAll(findFilesWithExtension(file, extension));
                    } else if (file.isFile() && file.getName().toLowerCase().endsWith(extension)) {
                        filePaths.add(file.getAbsolutePath());
                    }
                }
            }
        } else {
            filePaths.add(directory.getAbsolutePath());
        }
        return filePaths;
    }

    private String selectDirectory(boolean forDirectories) {
        JFileChooser chooser = new JFileChooser();
        chooser.setCurrentDirectory(new java.io.File(configLoader.getRulesFilePath()));
        chooser.setDialogTitle(String.format("Select a Directory%s", forDirectories ? "" : " or File"));
        FileNameExtensionFilter filter = new FileNameExtensionFilter(".hae Files", "hae");
        chooser.addChoosableFileFilter(filter);
        chooser.setFileFilter(filter);

        chooser.setFileSelectionMode(forDirectories ? JFileChooser.DIRECTORIES_ONLY : JFileChooser.FILES_AND_DIRECTORIES);
        chooser.setAcceptAllFileFilterUsed(!forDirectories);

        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedDirectory = chooser.getSelectedFile();
            return selectedDirectory.getAbsolutePath();
        }

        return "";
    }

    private void clearActionPerformed(ActionEvent e) {
        int retCode = JOptionPane.showConfirmDialog(this, "Do you want to clear data?", "Info",
                JOptionPane.YES_NO_OPTION);
        String host = hostTextField.getText();
        if (retCode == JOptionPane.YES_OPTION && !host.isEmpty()) {
            dataTabbedPane.removeAll();
            splitPane.setVisible(false);
            progressBar.setVisible(false);

            Config.globalDataMap.keySet().parallelStream().forEach(key -> {
                if (StringProcessor.matchesHostPattern(key, host) || host.equals("*")) {
                    Config.globalDataMap.remove(key);
                }
            });

            if (!StringProcessor.matchHostIsIp(host) && !host.contains("*.")) {
                String baseDomain = StringProcessor.getBaseDomain(StringProcessor.extractHostname(host));

                long count = Config.globalDataMap.keySet().stream()
                        .filter(k -> !k.equals("*." + baseDomain))
                        .filter(k -> StringProcessor.matchFromEnd(k, baseDomain))
                        .count();

                if (count == 0) {
                    Config.globalDataMap.remove("*." + baseDomain);
                }
            }

            if (Config.globalDataMap.keySet().size() == 1 && Config.globalDataMap.keySet().stream().anyMatch(key -> key.contains("*"))) {
                Config.globalDataMap.keySet().remove("*");
            }

            messageTableModel.deleteByHost(host);
        }
    }
}
