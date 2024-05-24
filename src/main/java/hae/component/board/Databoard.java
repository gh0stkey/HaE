package hae.component.board;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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
import java.util.concurrent.ConcurrentHashMap;
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

    private static Boolean isMatchHost = false;
    private final DefaultComboBoxModel comboBoxModel = new DefaultComboBoxModel();
    private final JComboBox hostComboBox = new JComboBox(comboBoxModel);

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
        ((GridBagLayout) getLayout()).rowHeights = new int[]{0, 65, 20, 0};
        ((GridBagLayout) getLayout()).columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, 0.0, 1.0E-4};
        ((GridBagLayout) getLayout()).rowWeights = new double[]{0.0, 1.0, 0.0, 1.0E-4};

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

        actionButton.addActionListener(e -> {
            int x = 0;
            int y = actionButton.getHeight();
            menu.show(actionButton, x, y);
        });

        clearButton.addActionListener(this::clearActionPerformed);
        exportButton.addActionListener(this::exportActionPerformed);
        importButton.addActionListener(this::importActionPerformed);

        splitPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                resizePanel();
            }
        });

        splitPane.setVisible(false);

        add(hostLabel, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(hostTextField, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(actionButton, new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
        add(splitPane, new GridBagConstraints(1, 1, 3, 3, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));
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
            String selectedHost = hostComboBox.getSelectedItem().toString();
            hostTextField.setText(selectedHost);
            populateTabbedPaneByHost(selectedHost);
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
            hostComboBox.setPopupVisible(false);
        }

        if (keyCode == KeyEvent.VK_ESCAPE) {
            hostComboBox.setPopupVisible(false);
        }

        isMatchHost = false;
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

    private void populateTabbedPaneByHost(String selectedHost) {
        if (!Objects.equals(selectedHost, "")) {
            ConcurrentHashMap<String, Map<String, List<String>>> dataMap = Config.globalDataMap;
            Map<String, List<String>> selectedDataMap;

            dataTabbedPane.removeAll();
            dataTabbedPane.setPreferredSize(new Dimension(500, 0));
            dataTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
            splitPane.setLeftComponent(dataTabbedPane);

            if (selectedHost.contains("*")) {
                // 通配符数据
                selectedDataMap = new HashMap<>();
                for (String key : dataMap.keySet()) {
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
                }
            } else {
                selectedDataMap = dataMap.get(selectedHost);
            }

            for (Map.Entry<String, List<String>> entry : selectedDataMap.entrySet()) {
                String tabTitle = String.format("%s (%s)", entry.getKey(), entry.getValue().size());
                Datatable datatablePanel = new Datatable(api, entry.getKey(), entry.getValue());
                datatablePanel.setTableListener(messageTableModel);
                dataTabbedPane.addTab(tabTitle, datatablePanel);
            }

            // 展示请求消息表单
            JSplitPane messageSplitPane = messageTableModel.getSplitPane();
            this.splitPane.setRightComponent(messageSplitPane);
            messageTable = messageTableModel.getMessageTable();

            resizePanel();
            splitPane.setVisible(true);

            applyHostFilter(selectedHost);
            hostTextField.setText(selectedHost);
        }
    }

    private void applyHostFilter(String filterText) {
        TableRowSorter<TableModel> sorter = (TableRowSorter<TableModel>) messageTable.getRowSorter();

        String cleanedText = StringProcessor.replaceFirstOccurrence(filterText, "*.", "");

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
    }

    private List<String> getHostByList() {
        if (!(Config.globalDataMap.keySet().size() == 1 && Config.globalDataMap.keySet().stream().anyMatch(key -> key.contains("*")))) {
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

        ConcurrentHashMap<String, Map<String, List<String>>> dataMap = Config.globalDataMap;
        List<String> taskStatusList = exportData(selectedHost, exportDir, dataMap);

        if (!taskStatusList.isEmpty()) {
            String exportStatusMessage = String.format("Exported File List Status:\n%s", String.join("\n", taskStatusList));
            JOptionPane.showConfirmDialog(null, exportStatusMessage, "Info", JOptionPane.YES_OPTION);
        }
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
        Map<String, Map<String, String>> httpMap = messageEntryList.stream()
                .filter(messageEntry -> !StringProcessor.getHostByUrl(messageEntry.getUrl()).isEmpty())
                .filter(messageEntry -> StringProcessor.getHostByUrl(messageEntry.getUrl()).equals(key))
                .collect(Collectors.toMap(
                        MessageEntry::getUrl,
                        this::createHttpItemMap,
                        (existing, replacement) -> existing
                ));

        String hostName = key.replace(":", "_");
        String filename = String.format("%s/%s.hae", exportDir, hostName);
        boolean createdStatus = projectProcessor.createHaeFile(filename, key, ruleMap, httpMap);

        return String.format("Filename: %s, Status: %s", filename, createdStatus);
    }

    private Map<String, String> createHttpItemMap(MessageEntry entry) {
        Map<String, String> httpItemMap = new HashMap<>();
        httpItemMap.put("comment", entry.getComment());
        httpItemMap.put("color", entry.getColor());
        httpItemMap.put("request", entry.getRequestResponse().request().toString());
        httpItemMap.put("response", entry.getRequestResponse().response().toString());
        return httpItemMap;
    }

    private void importActionPerformed(ActionEvent e) {
        String exportDir = selectDirectory(false);
        if (exportDir.isEmpty()) {
            return;
        }

        List<String> filesWithExtension = findFilesWithExtension(new File(exportDir), ".hae");
        List<String> taskStatusList = filesWithExtension.stream()
                .map(this::importData)
                .collect(Collectors.toList());

        if (!taskStatusList.isEmpty()) {
            String importStatusMessage = "Imported File List Status:\n" + String.join("\n", taskStatusList);
            JOptionPane.showConfirmDialog(null, importStatusMessage, "Info", JOptionPane.YES_OPTION);
        }
    }

    private String importData(String filename) {
        HaeFileContent haeFileContent = projectProcessor.readHaeFile(filename);
        boolean readStatus = haeFileContent != null;

        if (readStatus) {
            String host = haeFileContent.getHost();
            haeFileContent.getDataMap().forEach((key, value) -> RegularMatcher.putDataToGlobalMap(host, key, value));

            haeFileContent.getHttpMap().forEach((key, httpItemMap) -> {
                String comment = httpItemMap.get("comment");
                String color = httpItemMap.get("color");
                HttpRequestResponse httpRequestResponse = createHttpRequestResponse(key, httpItemMap);
                messageTableModel.add(httpRequestResponse, comment, color);
            });
        }

        return String.format("Filename: %s, Status: %s", filename, readStatus);
    }

    private HttpRequestResponse createHttpRequestResponse(String key, Map<String, String> httpItemMap) {
        HttpService httpService = HttpService.httpService(key);
        HttpRequest httpRequest = HttpRequest.httpRequest(httpService, httpItemMap.get("request"));
        HttpResponse httpResponse = HttpResponse.httpResponse(httpItemMap.get("response"));
        return HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse);
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
        }
        filePaths.add(directory.getAbsolutePath());
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
        int retCode = JOptionPane.showConfirmDialog(null, "Do you want to clear data?", "Info",
                JOptionPane.YES_NO_OPTION);
        String host = hostTextField.getText();
        if (retCode == JOptionPane.YES_OPTION && !host.isEmpty()) {
            dataTabbedPane.removeAll();
            splitPane.setVisible(false);

            String cleanedHost = StringProcessor.replaceFirstOccurrence(host, "*.", "");

            if (host.contains("*")) {
                Config.globalDataMap.keySet().removeIf(i -> i.contains(cleanedHost) || cleanedHost.contains("*"));
            } else {
                Config.globalDataMap.remove(host);
            }

            messageTableModel.deleteByHost(host);
        }
    }
}
