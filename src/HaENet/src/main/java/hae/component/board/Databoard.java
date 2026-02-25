package hae.component.board;

import burp.api.montoya.MontoyaApi;
import hae.cache.DataCache;
import hae.component.board.message.MessageTableModel;
import hae.component.board.message.MessageTableModel.MessageTable;
import hae.component.board.table.Datatable;
import hae.repository.DataRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.UIEnhancer;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.text.Collator;
import java.util.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Databoard extends JPanel {
    private boolean isMatchHost = false;
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final MessageTableModel messageTableModel;
    private final DataRepository dataRepository;
    private final ValidatorService validatorService;
    private final DefaultComboBoxModel<String> comboBoxModel = new DefaultComboBoxModel<>();
    private final JComboBox<String> hostComboBox = new JComboBox<>(comboBoxModel);
    private JTextField hostTextField;
    private JTabbedPane dataTabbedPane;
    private JSplitPane splitPane;
    private MessageTable messageTable;
    private JProgressBar progressBar;
    private SwingWorker<Map<String, List<String>>, Integer> handleComboBoxWorker;
    private SwingWorker<Void, Void> applyHostFilterWorker;

    public Databoard(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel,
                     DataRepository dataRepository, ValidatorService validatorService) {
        this.api = api;
        this.configLoader = configLoader;
        this.messageTableModel = messageTableModel;
        this.dataRepository = dataRepository;
        this.validatorService = validatorService;

        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        ((GridBagLayout) getLayout()).columnWidths = new int[]{25, 0, 0, 0, 20, 0};
        ((GridBagLayout) getLayout()).rowHeights = new int[]{0, 65, 20, 0, 0};
        ((GridBagLayout) getLayout()).columnWeights = new double[]{0.0, 0.0, 1.0, 0.0, 0.0, 1.0E-4};
        ((GridBagLayout) getLayout()).rowWeights = new double[]{0.0, 1.0, 0.0, 0.0, 1.0E-4};
        JLabel hostLabel = new JLabel("Host:");

        JButton clearDataButton = new JButton("Clear data");
        JButton clearCacheButton = new JButton("Clear cache");
        JButton actionButton = new JButton("Action");
        JPanel menuPanel = new JPanel(new GridLayout(2, 1, 0, 5));
        menuPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        JPopupMenu menu = new JPopupMenu();
        menuPanel.add(clearDataButton);
        menuPanel.add(clearCacheButton);
        menu.add(menuPanel);

        hostTextField = new JTextField();
        String defaultText = "Please enter the host";
        UIEnhancer.setTextFieldPlaceholder(hostTextField, defaultText);
        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);
        dataTabbedPane.setPreferredSize(new Dimension(500, 0));
        dataTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        dataTabbedPane.addChangeListener(e -> {
            int selectedIndex = dataTabbedPane.getSelectedIndex();
            String selectedTitle = "";
            if (selectedIndex != -1) {
                selectedTitle = dataTabbedPane.getTitleAt(selectedIndex);
            }

            String finalTitle = selectedTitle;
            new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() {
                    messageTableModel.applyCommentFilter(StringProcessor.extractItemName(finalTitle));
                    return null;
                }
            }.execute();
        });

        dataTabbedPane.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { showTabPopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { showTabPopup(e); }
            private void showTabPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int tabIndex = dataTabbedPane.indexAtLocation(e.getX(), e.getY());
                    if (tabIndex != -1) {
                        JPopupMenu popup = new JPopupMenu();
                        JMenuItem revalidateItem = new JMenuItem("Revalidate");
                        revalidateItem.addActionListener(ev -> revalidateTab(tabIndex));
                        popup.add(revalidateItem);
                        popup.show(dataTabbedPane, e.getX(), e.getY());
                    }
                }
            }
        });

        actionButton.addActionListener(e -> {
            int x = 0;
            int y = actionButton.getHeight();
            menu.show(actionButton, x, y);
        });

        clearDataButton.addActionListener(this::clearDataActionPerformed);
        clearCacheButton.addActionListener(this::clearCacheActionPerformed);

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
        add(progressBar, new GridBagConstraints(1, 2, 3, 1, 1.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.HORIZONTAL,
                new Insets(0, 5, 0, 5), 0, 0));
        hostComboBox.setMaximumRowCount(5);
        add(hostComboBox, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0, GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(8, 0, 5, 5), 0, 0));

        setAutoMatch();
    }

    private void resizePanel() {
        if (messageTable == null) {
            return;
        }
        splitPane.setDividerLocation(0.4);
        TableColumnModel columnModel = messageTable.getColumnModel();
        int totalWidth = (int) (getWidth() * 0.6);
        columnModel.getColumn(0).setPreferredWidth((int) (totalWidth * 0.05));
        columnModel.getColumn(1).setPreferredWidth((int) (totalWidth * 0.08));
        columnModel.getColumn(2).setPreferredWidth((int) (totalWidth * 0.3));
        columnModel.getColumn(3).setPreferredWidth((int) (totalWidth * 0.27));
        columnModel.getColumn(4).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(5).setPreferredWidth((int) (totalWidth * 0.1));
        columnModel.getColumn(6).setPreferredWidth((int) (totalWidth * 0.1));
    }

    private void setProgressBar(boolean status, String message, int progress) {
        progressBar.setIndeterminate(status && progress <= 0);
        progressBar.setString(message);
        progressBar.setStringPainted(true);
        progressBar.setMaximum(100);

        if (progress > 0) {
            progressBar.setValue(progress);
        } else if (!status) {
            progressBar.setValue(progressBar.getMaximum());
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
            String selectedHost = hostComboBox.getSelectedItem().toString();

            if (getHostByList().contains(selectedHost)) {
                hostTextField.setText(selectedHost);
                hostComboBox.setPopupVisible(false);

                if (handleComboBoxWorker != null && !handleComboBoxWorker.isDone()) {
                    progressBar.setVisible(false);
                    handleComboBoxWorker.cancel(true);
                }

                handleComboBoxWorker = new DataLoadingWorker(selectedHost);

                handleComboBoxWorker.execute();
            }
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

    private Map<String, List<String>> getSelectedMapByHost(String selectedHost, DataLoadingWorker worker) {
        Map<String, Map<String, List<String>>> dataMap = dataRepository.getAll();
        Map<String, List<String>> selectedDataMap;

        if (selectedHost.contains("*")) {
            selectedDataMap = new HashMap<>();
            List<String> matchingKeys = new ArrayList<>();

            // 第一步：找出所有匹配的键（预处理）
            for (String key : dataMap.keySet()) {
                if ((StringProcessor.matchesHostPattern(key, selectedHost) || selectedHost.equals("*")) && !key.contains("*")) {
                    matchingKeys.add(key);
                }
            }

            // 第二步：分批处理数据
            int totalKeys = matchingKeys.size();
            for (int i = 0; i < totalKeys; i++) {
                String key = matchingKeys.get(i);
                Map<String, List<String>> ruleMap = dataMap.get(key);

                if (ruleMap != null) {
                    for (String ruleKey : ruleMap.keySet()) {
                        List<String> dataList = ruleMap.get(ruleKey);
                        if (selectedDataMap.containsKey(ruleKey)) {
                            List<String> mergedList = new ArrayList<>(selectedDataMap.get(ruleKey));
                            mergedList.addAll(dataList);
                            // 使用HashSet去重
                            Set<String> uniqueSet = new HashSet<>(mergedList);
                            selectedDataMap.put(ruleKey, new ArrayList<>(uniqueSet));
                        } else {
                            selectedDataMap.put(ruleKey, new ArrayList<>(dataList));
                        }
                    }
                }

                // 报告进度
                if (worker != null && i % 5 == 0) {
                    int progress = (int) ((i + 1) * 90.0 / totalKeys);
                    worker.publishProgress(progress);
                }
            }
        } else {
            selectedDataMap = dataMap.get(selectedHost);
            // 对于非通配符匹配，直接返回结果
            if (worker != null) {
                worker.publishProgress(90);
            }
        }

        return selectedDataMap != null ? selectedDataMap : new HashMap<>();
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

        if (applyHostFilterWorker != null && !applyHostFilterWorker.isDone()) {
            applyHostFilterWorker.cancel(true);
        }

        applyHostFilterWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                messageTableModel.applyHostFilter(filterText);
                return null;
            }

            @Override
            protected void done() {
                if (!isCancelled()) {
                    RowFilter<Object, Object> rowFilter = new RowFilter<>() {
                        public boolean include(Entry<?, ?> entry) {
                            if (cleanedText.equals("*")) {
                                return true;
                            } else {
                                String host = StringProcessor.getHostByUrl((String) entry.getValue(2));
                                return StringProcessor.matchesHostPattern(host, filterText);
                            }
                        }
                    };
                    sorter.setRowFilter(rowFilter);
                }
            }
        };

        applyHostFilterWorker.execute();
    }

    private List<String> getHostByList() {
        List<String> result = new ArrayList<>();
        if (!dataRepository.isEmpty()) {
            result = new ArrayList<>(dataRepository.getAllHosts());
        }

        return result;
    }

    private void clearCacheActionPerformed(ActionEvent e) {
        int retCode = JOptionPane.showConfirmDialog(this, "Do you want to clear cache?", "Info",
                JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            DataCache.clear();
        }
    }

    private void clearDataActionPerformed(ActionEvent e) {
        int retCode = JOptionPane.showConfirmDialog(this, "Do you want to clear data?", "Info",
                JOptionPane.YES_NO_OPTION);
        String host = hostTextField.getText();
        if (retCode == JOptionPane.YES_OPTION && !host.isEmpty()) {
            dataTabbedPane.removeAll();
            splitPane.setVisible(false);
            progressBar.setVisible(false);

            dataRepository.removeMatching(host);

            messageTableModel.deleteByHost(host);

            hostTextField.setText("");
        }
    }

    private void revalidateTab(int tabIndex) {
        Component comp = dataTabbedPane.getComponentAt(tabIndex);
        if (!(comp instanceof Datatable dt)) return;

        List<String> matches = new ArrayList<>();
        JTable table = dt.getDataTable();
        for (int r = 0; r < table.getModel().getRowCount(); r++) {
            matches.add(table.getModel().getValueAt(r, 1).toString());
        }
        if (matches.isEmpty()) return;

        progressBar.setVisible(true);
        setProgressBar(true, "Validating...", 0);

        validatorService.revalidateAll(Map.of(dt.getTabName(), matches), null, () ->
                SwingUtilities.invokeLater(() -> {
                    dt.refreshSeverities();
                    setProgressBar(false, "Validation complete", 100);
                })
        );
    }

    // 定义为内部类
    private class DataLoadingWorker extends SwingWorker<Map<String, List<String>>, Integer> {
        private final String selectedHost;

        public DataLoadingWorker(String selectedHost) {
            this.selectedHost = selectedHost;
            progressBar.setVisible(true);
        }

        @Override
        protected Map<String, List<String>> doInBackground() throws Exception {
            return getSelectedMapByHost(selectedHost, this);
        }

        @Override
        protected void process(List<Integer> chunks) {
            if (!chunks.isEmpty()) {
                int progress = chunks.get(chunks.size() - 1);
                setProgressBar(true, "Loading... " + progress + "%", progress);
            }
        }

        @Override
        protected void done() {
            if (!isCancelled()) {
                try {
                    Map<String, List<String>> selectedDataMap = get();
                    if (selectedDataMap != null && !selectedDataMap.isEmpty()) {
                        dataTabbedPane.removeAll();

                        for (Map.Entry<String, List<String>> entry : selectedDataMap.entrySet()) {
                            String tabTitle = String.format("%s (%s)", entry.getKey(), entry.getValue().size());
                            Datatable datatablePanel = new Datatable(api, configLoader, entry.getKey(), entry.getValue(), validatorService);
                            datatablePanel.setTableListener(messageTableModel);
                            Databoard.insertTabSorted(dataTabbedPane, tabTitle, datatablePanel);
                        }

                        JSplitPane messageSplitPane = messageTableModel.getSplitPane();
                        splitPane.setLeftComponent(dataTabbedPane);
                        splitPane.setRightComponent(messageSplitPane);
                        messageTable = messageTableModel.getMessageTable();
                        resizePanel();

                        splitPane.setVisible(true);
                        dataTabbedPane.setSelectedIndex(0);
                        applyHostFilter(selectedHost);
                        setProgressBar(false, "OK", 100);
                    } else {
                        setProgressBar(false, "Error", 0);
                    }
                } catch (Exception e) {
                    api.logging().logToOutput("DataLoadingWorker: " + e.getMessage());
                    setProgressBar(false, "Error", 0);
                }
            }
        }

        // 提供一个公共方法来发布进度
        public void publishProgress(int progress) {
            publish(progress);
        }
    }

    private static void insertTabSorted(JTabbedPane tabbedPane, String title, Component component) {
        int insertIndex = 0;
        int tabCount = tabbedPane.getTabCount();

        // 使用 Collator 实现更友好的语言排序（支持中文、特殊字符等）
        Collator collator = Collator.getInstance(Locale.getDefault());
        collator.setStrength(Collator.PRIMARY); // 忽略大小写和重音

        for (int i = 0; i < tabCount; i++) {
            String existingTitle = tabbedPane.getTitleAt(i);
            if (collator.compare(existingTitle, title) > 0) {
                insertIndex = i;
                break;
            }
            insertIndex = i + 1;
        }

        tabbedPane.insertTab(title, null, component, null, insertIndex);
    }
}
