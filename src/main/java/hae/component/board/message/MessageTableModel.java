package hae.component.board.message;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import hae.Config;
import hae.utils.ConfigLoader;
import hae.utils.DataManager;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;

public class MessageTableModel extends AbstractTableModel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final MessageTable messageTable;
    private final JSplitPane splitPane;
    private final LinkedList<MessageEntry> log = new LinkedList<>();
    private final LinkedList<MessageEntry> filteredLog;
    private SwingWorker<Void, Void> currentWorker;

    public MessageTableModel(MontoyaApi api, ConfigLoader configLoader) {
        this.filteredLog = new LinkedList<>();
        this.api = api;
        this.configLoader = configLoader;

        JTabbedPane messageTab = new JTabbedPane();
        UserInterface userInterface = api.userInterface();
        HttpRequestEditor requestViewer = userInterface.createHttpRequestEditor(READ_ONLY);
        HttpResponseEditor responseViewer = userInterface.createHttpResponseEditor(READ_ONLY);
        messageTab.addTab("Request", requestViewer.uiComponent());
        messageTab.addTab("Response", responseViewer.uiComponent());

        // 请求条目表格
        messageTable = new MessageTable(MessageTableModel.this, requestViewer, responseViewer);
        messageTable.setDefaultRenderer(Object.class, new MessageRenderer(filteredLog, messageTable));
        messageTable.setAutoCreateRowSorter(true);

        // Length字段根据大小进行排序
        TableRowSorter<DefaultTableModel> sorter = getDefaultTableModelTableRowSorter();
        messageTable.setRowSorter(sorter);
        messageTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        // 请求/响应文本框
        JScrollPane scrollPane = new JScrollPane(messageTable);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        splitPane.setLeftComponent(scrollPane);
        splitPane.setRightComponent(messageTab);
    }

    private TableRowSorter<DefaultTableModel> getDefaultTableModelTableRowSorter() {
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) messageTable.getRowSorter();
        sorter.setComparator(4, (Comparator<String>) (s1, s2) -> {
            Integer age1 = Integer.parseInt(s1);
            Integer age2 = Integer.parseInt(s2);
            return age1.compareTo(age2);
        });

        // Color字段根据颜色顺序进行排序
        sorter.setComparator(5, new Comparator<String>() {
            @Override
            public int compare(String s1, String s2) {
                int index1 = getIndex(s1);
                int index2 = getIndex(s2);
                return Integer.compare(index1, index2);
            }

            private int getIndex(String color) {
                for (int i = 0; i < Config.color.length; i++) {
                    if (Config.color[i].equals(color)) {
                        return i;
                    }
                }
                return -1;
            }
        });
        return sorter;
    }

    public synchronized void add(HttpRequestResponse messageInfo, String url, String method, String status, String length, String comment, String color, boolean flag) {
        synchronized (log) {
            if (messageInfo == null) {
                return;
            }

            boolean isDuplicate = false;
            try {
                if (!log.isEmpty() && flag) {
                    String host = StringProcessor.getHostByUrl(url);

                    for (MessageEntry entry : log) {
                        if (host.equals(StringProcessor.getHostByUrl(entry.getUrl()))) {
                            if (isRequestDuplicate(
                                    messageInfo, entry.getRequestResponse(),
                                    url, entry.getUrl(),
                                    comment, entry.getComment(),
                                    color, entry.getColor()
                            )) {
                                isDuplicate = true;
                                break;
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }

            if (!isDuplicate) {
                if (flag) {
                    persistData(messageInfo, comment, color);
                }
                log.add(new MessageEntry(messageInfo, method, url, comment, length, color, status));
            }
        }
    }

    private boolean isRequestDuplicate(
            HttpRequestResponse newReq, HttpRequestResponse existingReq,
            String newUrl, String existingUrl,
            String newComment, String existingComment,
            String newColor, String existingColor) {
        try {
            // 基础属性匹配
            String normalizedNewUrl = normalizeUrl(newUrl);
            String normalizedExistingUrl = normalizeUrl(existingUrl);
            boolean basicMatch = normalizedNewUrl.equals(normalizedExistingUrl);

            // 请求响应内容匹配
            byte[] newReqBytes = newReq.request().toByteArray().getBytes();
            byte[] newResBytes = newReq.response().toByteArray().getBytes();
            byte[] existingReqBytes = existingReq.request().toByteArray().getBytes();
            byte[] existingResBytes = existingReq.response().toByteArray().getBytes();
            boolean contentMatch = Arrays.equals(newReqBytes, existingReqBytes) &&
                    Arrays.equals(newResBytes, existingResBytes);

            // 注释和颜色匹配
            boolean metadataMatch = areCommentsEqual(newComment, existingComment) &&
                    newColor.equals(existingColor);

            return (basicMatch || contentMatch) && metadataMatch;
        } catch (Exception e) {
            return false;
        }
    }

    private String normalizeUrl(String url) {
        if (url == null) {
            return "";
        }

        String normalized = url.trim().toLowerCase();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        return normalized.replaceAll("//", "/");
    }

    private boolean areCommentsEqual(String comment1, String comment2) {
        if (comment1 == null || comment2 == null) {
            return false;
        }

        try {
            // 将注释按规则拆分并排序
            Set<String> rules1 = new TreeSet<>(Arrays.asList(comment1.split(", ")));
            Set<String> rules2 = new TreeSet<>(Arrays.asList(comment2.split(", ")));

            return rules1.equals(rules2);
        } catch (Exception e) {
            return false;
        }
    }

    private void persistData(HttpRequestResponse messageInfo, String comment, String color) {
        try {
            DataManager dataManager = new DataManager(api);
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
        filteredLog.clear();
        List<Integer> rowsToRemove = new ArrayList<>();

        if (currentWorker != null && !currentWorker.isDone()) {
            currentWorker.cancel(true);
        }

        currentWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
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

                return null;
            }
        };

        currentWorker.execute();
    }

    public void applyHostFilter(String filterText) {
        filteredLog.clear();
        fireTableDataChanged();

        int batchSize = 500;

        // 分批处理数据
        List<MessageEntry> batch = new ArrayList<>(batchSize);
        int count = 0;

        for (MessageEntry entry : log) {
            String host = StringProcessor.getHostByUrl(entry.getUrl());
            if (!host.isEmpty() && (StringProcessor.matchesHostPattern(host, filterText) || filterText.contains("*"))) {
                batch.add(entry);
                count++;

                // 当批次达到指定大小时，更新UI
                if (count % batchSize == 0) {
                    final List<MessageEntry> currentBatch = new ArrayList<>(batch);
                    SwingUtilities.invokeLater(() -> {
                        filteredLog.addAll(currentBatch);
                        fireTableDataChanged();
                    });
                    batch.clear();
                }
            }
        }

        // 处理最后一批
        if (!batch.isEmpty()) {
            final List<MessageEntry> finalBatch = new ArrayList<>(batch);
            SwingUtilities.invokeLater(() -> {
                filteredLog.addAll(finalBatch);
                fireTableDataChanged();
            });
        }
    }

    public void applyMessageFilter(String tableName, String filterText) {
        filteredLog.clear();
        for (MessageEntry entry : log) {
            // 标志变量，表示是否满足过滤条件
            AtomicBoolean isMatched = new AtomicBoolean(false);

            HttpRequestResponse requestResponse = entry.getRequestResponse();
            HttpRequest httpRequest = requestResponse.request();
            HttpResponse httpResponse = requestResponse.response();

            String requestString = new String(httpRequest.toByteArray().getBytes(), StandardCharsets.UTF_8);
            String requestBody = new String(httpRequest.body().getBytes(), StandardCharsets.UTF_8);
            String requestHeaders = httpRequest.headers().stream()
                    .map(HttpHeader::toString)
                    .collect(Collectors.joining("\r\n"));

            String responseString = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
            String responseBody = new String(httpResponse.body().getBytes(), StandardCharsets.UTF_8);
            String responseHeaders = httpResponse.headers().stream()
                    .map(HttpHeader::toString)
                    .collect(Collectors.joining("\r\n"));

            Config.globalRules.keySet().forEach(i -> {
                for (Object[] objects : Config.globalRules.get(i)) {
                    String name = objects[1].toString();
                    String format = objects[4].toString();
                    String scope = objects[6].toString();

                    // 从注释中查看是否包含当前规则名，包含的再进行查询，有效减少无意义的检索时间
                    if (entry.getComment().contains(name)) {
                        if (name.equals(tableName)) {
                            // 标志变量，表示当前规则是否匹配
                            boolean isMatch = false;

                            switch (scope) {
                                case "any":
                                    isMatch = matchingString(format, filterText, requestString) || matchingString(format, filterText, responseString);
                                    break;
                                case "request":
                                    isMatch = matchingString(format, filterText, requestString);
                                    break;
                                case "response":
                                    isMatch = matchingString(format, filterText, responseString);
                                    break;
                                case "any header":
                                    isMatch = matchingString(format, filterText, requestHeaders) || matchingString(format, filterText, responseHeaders);
                                    break;
                                case "request header":
                                    isMatch = matchingString(format, filterText, requestHeaders);
                                    break;
                                case "response header":
                                    isMatch = matchingString(format, filterText, responseHeaders);
                                    break;
                                case "any body":
                                    isMatch = matchingString(format, filterText, requestBody) || matchingString(format, filterText, responseBody);
                                    break;
                                case "request body":
                                    isMatch = matchingString(format, filterText, requestBody);
                                    break;
                                case "response body":
                                    isMatch = matchingString(format, filterText, responseBody);
                                    break;
                                case "request line":
                                    String requestLine = requestString.split("\\r?\\n", 2)[0];
                                    isMatch = matchingString(format, filterText, requestLine);
                                    break;
                                case "response line":
                                    String responseLine = responseString.split("\\r?\\n", 2)[0];
                                    isMatch = matchingString(format, filterText, responseLine);
                                    break;
                                default:
                                    break;
                            }

                            isMatched.set(isMatch);
                            break;
                        }
                    }
                }
            });

            if (isMatched.get()) {
                filteredLog.add(entry);
            }
        }

        fireTableDataChanged();
        messageTable.lastSelectedIndex = -1;
    }

    private boolean matchingString(String format, String filterText, String target) {
        boolean isMatch = true;

        try {
            MessageFormat mf = new MessageFormat(format);
            Object[] parsedObjects = mf.parse(filterText);

            for (Object parsedObject : parsedObjects) {
                if (!target.contains(parsedObject.toString())) {
                    isMatch = false;
                    break;
                }
            }
        } catch (Exception e) {
            isMatch = false;
        }

        return isMatch;
    }

    public JSplitPane getSplitPane() {
        return splitPane;
    }

    public MessageTable getMessageTable() {
        return messageTable;
    }

    @Override
    public int getRowCount() {
        return filteredLog.size();
    }

    @Override
    public int getColumnCount() {
        return 6;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (!filteredLog.isEmpty()) {
            try {
                MessageEntry messageEntry = filteredLog.get(rowIndex);

                if (messageEntry != null) {
                    return switch (columnIndex) {
                        case 0 -> messageEntry.getMethod();
                        case 1 -> messageEntry.getUrl();
                        case 2 -> messageEntry.getComment();
                        case 3 -> messageEntry.getStatus();
                        case 4 -> messageEntry.getLength();
                        case 5 -> messageEntry.getColor();
                        default -> "";
                    };
                }
            } catch (Exception e) {
                api.logging().logToError("getValueAt: " + e.getMessage());
            }
        }

        return "";
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "Method";
            case 1 -> "URL";
            case 2 -> "Comment";
            case 3 -> "Status";
            case 4 -> "Length";
            case 5 -> "Color";
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
            MessageEntry messageEntry = filteredLog.get(lastSelectedIndex);

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
