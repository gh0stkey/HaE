package hae.component.board.message;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import hae.AppConstants;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;
import hae.utils.DataManager;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class MessageTableModel extends AbstractTableModel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final DataManager dataManager;
    private final MessageDeduplicator deduplicator;
    private final MessageFilter messageFilter;
    private final MessageTable messageTable;
    private final JSplitPane splitPane;
    private final LinkedList<MessageEntry> log = new LinkedList<>();
    private final LinkedList<MessageEntry> filteredLog;
    private SwingWorker<Void, Void> currentWorker;

    public MessageTableModel(MontoyaApi api, ConfigLoader configLoader, RuleRepository ruleRepository) {
        this.filteredLog = new LinkedList<>();
        this.api = api;
        this.configLoader = configLoader;
        this.dataManager = new DataManager(api);
        this.deduplicator = new MessageDeduplicator(configLoader);
        this.messageFilter = new MessageFilter(ruleRepository);

        UserInterface userInterface = api.userInterface();
        HttpRequestEditor requestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
        HttpResponseEditor responseViewer = userInterface.createHttpResponseEditor(READ_ONLY);
        JSplitPane messagePane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        messagePane.setLeftComponent(requestViewer.uiComponent());
        messagePane.setRightComponent(responseViewer.uiComponent());
        messagePane.setResizeWeight(0.5);

        // 请求条目表格
        messageTable = new MessageTable(MessageTableModel.this, requestViewer, responseViewer);
        MessageRenderer renderer = new MessageRenderer(filteredLog, messageTable);
        messageTable.setDefaultRenderer(Object.class, renderer);
        messageTable.setDefaultRenderer(Integer.class, renderer);
        messageTable.setAutoCreateRowSorter(true);

        TableRowSorter<DefaultTableModel> sorter = getDefaultTableModelTableRowSorter();
        messageTable.setRowSorter(sorter);
        messageTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                splitPane.setDividerLocation(0.3);
            }
        });
        // 请求/响应文本框
        JScrollPane scrollPane = new JScrollPane(messageTable);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        splitPane.setLeftComponent(scrollPane);
        splitPane.setRightComponent(messagePane);
    }

    private TableRowSorter<DefaultTableModel> getDefaultTableModelTableRowSorter() {
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) messageTable.getRowSorter();

        // Length字段根据大小进行排序
        sorter.setComparator(5, (Comparator<String>) (s1, s2) -> {
            Integer len1 = Integer.parseInt(s1);
            Integer len2 = Integer.parseInt(s2);
            return len1.compareTo(len2);
        });

        // Color字段根据颜色顺序进行排序
        sorter.setComparator(6, new Comparator<String>() {
            @Override
            public int compare(String s1, String s2) {
                int index1 = getIndex(s1);
                int index2 = getIndex(s2);
                return Integer.compare(index1, index2);
            }

            private int getIndex(String color) {
                for (int i = 0; i < AppConstants.color.length; i++) {
                    if (AppConstants.color[i].equals(color)) {
                        return i;
                    }
                }
                return -1;
            }
        });
        return sorter;
    }

    public void add(HttpRequestResponse messageInfo, String url, String method, String status, String length, String comment, String color, boolean persistAndDeduplicate) {
        synchronized (log) {
            if (messageInfo == null) {
                return;
            }

            if (comment == null || comment.trim().isEmpty()) {
                return;
            }

            if (color == null || color.trim().isEmpty()) {
                return;
            }

            boolean isDuplicate = false;
            try {
                if (persistAndDeduplicate) {
                    isDuplicate = deduplicator.isDuplicate(log, messageInfo, url, comment, color);
                }
            } catch (Exception e) {
                api.logging().logToError("Deduplication check error: " + e.getMessage());
            }

            if (!isDuplicate) {
                if (persistAndDeduplicate) {
                    persistData(messageInfo, comment, color);
                }
                log.add(new MessageEntry(messageInfo, method, url, comment, length, color, status));
            }
        }
    }

    private void persistData(HttpRequestResponse messageInfo, String comment, String color) {
        try {
            PersistedObject persistedObject = PersistedObject.persistedObject();
            persistedObject.setHttpRequestResponse("messageInfo", messageInfo);
            persistedObject.setString("comment", comment);
            persistedObject.setString("color", color);
            String uuidIndex = StringProcessor.getRandomUUID();
            dataManager.putData("message", uuidIndex, persistedObject);
        } catch (Exception e) {
            api.logging().logToError("Data persistence error: " + e.getMessage());
        }
    }

    public void deleteByHost(String filterText) {
        if (currentWorker != null && !currentWorker.isDone()) {
            currentWorker.cancel(true);
        }

        currentWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                synchronized (log) {
                    List<Integer> rowsToRemove = new ArrayList<>();

                    for (int i = 0; i < log.size(); i++) {
                        MessageEntry entry = log.get(i);
                        String host = StringProcessor.getHostByUrl(entry.getUrl());
                        if (!host.isEmpty()) {
                            if (StringProcessor.matchesHostPattern(host, filterText) || filterText.equals("*")) {
                                rowsToRemove.add(i);
                            }
                        }
                    }

                    for (int i = rowsToRemove.size() - 1; i >= 0; i--) {
                        int row = rowsToRemove.get(i);
                        log.remove(row);
                    }
                }

                return null;
            }

            @Override
            protected void done() {
                if (!isCancelled()) {
                    synchronized (filteredLog) {
                        filteredLog.clear();
                    }
                    fireTableDataChanged();
                }
            }
        };

        currentWorker.execute();
    }

    public void applyHostFilter(String filterText) {
        // 创建log的安全副本
        final List<MessageEntry> logSnapshot;
        synchronized (log) {
            logSnapshot = new ArrayList<>(log);
        }

        List<MessageEntry> newFilteredLog = messageFilter.filterByHost(logSnapshot, filterText);

        // 一次性更新UI，避免频繁刷新
        SwingUtilities.invokeLater(() -> {
            synchronized (filteredLog) {
                filteredLog.clear();
                filteredLog.addAll(newFilteredLog);
            }
            fireTableDataChanged();
        });
    }

    public void applyMessageFilter(String tableName, String filterText) {
        // 创建log的安全副本以避免ConcurrentModificationException
        List<MessageEntry> logSnapshot;
        synchronized (log) {
            logSnapshot = new ArrayList<>(log);
        }

        List<MessageEntry> newFilteredLog;
        try {
            newFilteredLog = messageFilter.filterByMessage(logSnapshot, tableName, filterText);
        } catch (Exception e) {
            api.logging().logToError("applyMessageFilter error: " + e.getMessage());
            newFilteredLog = List.of();
        }

        // 在EDT线程中更新UI
        List<MessageEntry> finalFilteredLog = newFilteredLog;
        SwingUtilities.invokeLater(() -> {
            synchronized (filteredLog) {
                filteredLog.clear();
                filteredLog.addAll(finalFilteredLog);
            }
            fireTableDataChanged();
            messageTable.lastSelectedIndex = -1;
        });
    }

    public void applyCommentFilter(String tableName) {
        List<MessageEntry> logSnapshot;
        synchronized (log) {
            logSnapshot = new ArrayList<>(log);
        }

        List<MessageEntry> newFilteredLog = messageFilter.filterByComment(logSnapshot, tableName);

        SwingUtilities.invokeLater(() -> {
            synchronized (filteredLog) {
                filteredLog.clear();
                filteredLog.addAll(newFilteredLog);
            }
            fireTableDataChanged();
            messageTable.lastSelectedIndex = -1;
        });
    }

    public JSplitPane getSplitPane() {
        return splitPane;
    }

    public MessageTable getMessageTable() {
        return messageTable;
    }

    public void dispose() {
        messageTable.shutdown();
    }

    @Override
    public int getRowCount() {
        synchronized (filteredLog) {
            return filteredLog.size();
        }
    }

    @Override
    public int getColumnCount() {
        return 7;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (filteredLog) {
            if (rowIndex < 0 || rowIndex >= filteredLog.size()) {
                return "";
            }

            try {
                MessageEntry messageEntry = filteredLog.get(rowIndex);
                if (messageEntry == null) {
                    return "";
                }

                return switch (columnIndex) {
                    case 0 -> rowIndex + 1;
                    case 1 -> messageEntry.getMethod();
                    case 2 -> messageEntry.getUrl();
                    case 3 -> messageEntry.getComment();
                    case 4 -> messageEntry.getStatus();
                    case 5 -> messageEntry.getLength();
                    case 6 -> messageEntry.getColor();
                    default -> "";
                };
            } catch (Exception e) {
                api.logging().logToError("getValueAt: " + e.getMessage());
                return "";
            }
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "#";
            case 1 -> "Method";
            case 2 -> "URL";
            case 3 -> "Comment";
            case 4 -> "Status";
            case 5 -> "Length";
            case 6 -> "Color";
            default -> "";
        };
    }

    public class MessageTable extends JTable {
        private final ExecutorService executorService;
        private final HttpRequestEditor requestEditor;
        private final HttpResponseEditor responseEditor;
        private int lastSelectedIndex = -1;

        public MessageTable(TableModel messageTableModel, HttpRequestEditor requestEditor, HttpResponseEditor responseEditor) {
            super(messageTableModel);
            this.requestEditor = requestEditor;
            this.responseEditor = responseEditor;
            this.executorService = Executors.newSingleThreadExecutor();
        }

        public void shutdown() {
            executorService.shutdownNow();
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            super.changeSelection(row, col, toggle, extend);
            int selectedIndex = convertRowIndexToModel(row);
            if (lastSelectedIndex != selectedIndex) {
                lastSelectedIndex = selectedIndex;
                executorService.execute(this::getSelectedMessage);
            }
        }

        private void getSelectedMessage() {
            MessageEntry messageEntry;
            synchronized (filteredLog) {
                int index = lastSelectedIndex;
                if (index < 0 || index >= filteredLog.size()) {
                    return;
                }
                messageEntry = filteredLog.get(index);
            }

            HttpRequestResponse httpRequestResponse = messageEntry.getRequestResponse();

            requestEditor.setRequest(HttpRequest.httpRequest(messageEntry.getRequestResponse().httpService(), httpRequestResponse.request().toByteArray()));
            int responseSizeWithMb = httpRequestResponse.response().toString().length() / 1024 / 1024;
            if ((responseSizeWithMb < Integer.parseInt(configLoader.getLimitSize())) || configLoader.getLimitSize().equals("0")) {
                responseEditor.setResponse(httpRequestResponse.response());
            } else {
                responseEditor.setResponse(HttpResponse.httpResponse("Exceeds length limit."));
            }
        }
    }
}
