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
import hae.cache.CachePool;
import hae.utils.ConfigLoader;
import hae.utils.DataManager;
import hae.utils.string.HashCalculator;
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
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) messageTable.getRowSorter();
        sorter.setComparator(4, new Comparator<String>() {
            @Override
            public int compare(String s1, String s2) {
                Integer age1 = Integer.parseInt(s1);
                Integer age2 = Integer.parseInt(s2);
                return age1.compareTo(age2);
            }
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
        messageTable.setRowSorter(sorter);
        messageTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        // 请求/相应文本框
        JScrollPane scrollPane = new JScrollPane(messageTable);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        splitPane.setLeftComponent(scrollPane);
        splitPane.setRightComponent(messageTab);
    }

    public void add(HttpRequestResponse messageInfo, String url, String method, String status, String length, String comment, String color, boolean flag) {
        synchronized (log) {
            boolean isDuplicate = false;
            MessageEntry logEntry = new MessageEntry(messageInfo, method, url, comment, length, color, status);

            byte[] reqByteA = new byte[0];
            byte[] resByteA = new byte[0];

            if (messageInfo != null) {
                HttpRequest httpRequest = messageInfo.request();
                HttpResponse httpResponse = messageInfo.response();

                reqByteA = httpRequest.toByteArray().getBytes();
                resByteA = httpResponse.toByteArray().getBytes();
            }

            // 比较Hash，如若存在重复的请求或响应，则不放入消息内容里
            try {
                if (!log.isEmpty()) {
                    for (MessageEntry entry : log) {
                        HttpRequestResponse reqResMessage = entry.getRequestResponse();
                        byte[] reqByteB = reqResMessage.request().toByteArray().getBytes();
                        byte[] resByteB = reqResMessage.response().toByteArray().getBytes();
                        try {
                            // 通过URL、请求和响应报文、匹配数据内容，多维度进行对比
                            if ((entry.getUrl().equals(url) || (Arrays.equals(reqByteB, reqByteA) || Arrays.equals(resByteB, resByteA))) && (areMapsEqual(getCacheData(reqByteB), getCacheData(reqByteA)) && areMapsEqual(getCacheData(resByteB), getCacheData(resByteA)))) {
                                isDuplicate = true;
                                break;
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            } catch (Exception ignored) {
            }

            if (!isDuplicate) {
                if (flag) {
                    DataManager dataManager = new DataManager(api);
                    // 数据存储在BurpSuite空间内
                    PersistedObject persistedObject = PersistedObject.persistedObject();
                    persistedObject.setHttpRequestResponse("messageInfo", messageInfo);
                    persistedObject.setString("comment", comment);
                    persistedObject.setString("color", color);
                    String uuidIndex = StringProcessor.getRandomUUID();
                    dataManager.putData("message", uuidIndex, persistedObject);
                }

                // 添加进日志
                log.add(logEntry);
            }
        }

    }

    public void deleteByHost(String filterText) {
        filteredLog.clear();
        List<Integer> rowsToRemove = new ArrayList<>();

        if (currentWorker != null && !currentWorker.isDone()) {
            currentWorker.cancel(true);
        }

        currentWorker = new SwingWorker<Void, Void>() {
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

        log.forEach(entry -> {
            String host = StringProcessor.getHostByUrl(entry.getUrl());
            if (!host.isEmpty()) {
                if (StringProcessor.matchesHostPattern(host, filterText) || filterText.contains("*")) {
                    filteredLog.add(entry);
                }
            }
        });

        fireTableDataChanged();
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
                    .collect(Collectors.joining("\n"));

            String responseString = new String(httpResponse.toByteArray().getBytes(), StandardCharsets.UTF_8);
            String responseBody = new String(httpResponse.body().getBytes(), StandardCharsets.UTF_8);
            String responseHeaders = httpResponse.headers().stream()
                    .map(HttpHeader::toString)
                    .collect(Collectors.joining("\n"));

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

    private Map<String, Map<String, Object>> getCacheData(byte[] content) {
        String hashIndex = HashCalculator.calculateHash(content);
        return CachePool.get(hashIndex);
    }

    private boolean areMapsEqual(Map<String, Map<String, Object>> map1, Map<String, Map<String, Object>> map2) {
        if (map1 == null || map2 == null) {
            return false;
        }
        if (map1.size() != map2.size()) {
            return false;
        }

        for (String key : map1.keySet()) {
            if (!map2.containsKey(key)) {
                return false;
            }
            if (areInnerMapsEqual(map1.get(key), map2.get(key))) {
                return false;
            }
        }

        return true;
    }

    private boolean areInnerMapsEqual(Map<String, Object> innerMap1, Map<String, Object> innerMap2) {
        if (innerMap1.size() != innerMap2.size()) {
            return true;
        }

        for (String key : innerMap1.keySet()) {
            if (!innerMap2.containsKey(key)) {
                return true;
            }
            Object value1 = innerMap1.get(key);
            Object value2 = innerMap2.get(key);

            // 如果值是Map，则递归对比
            if (value1 instanceof Map && value2 instanceof Map) {
                if (areInnerMapsEqual((Map<String, Object>) value1, (Map<String, Object>) value2)) {
                    return true;
                }
            } else if (!value1.equals(value2)) {
                return true;
            }
        }

        return false;
    }

    public JSplitPane getSplitPane() {
        return splitPane;
    }

    public MessageTable getMessageTable() {
        return messageTable;
    }

    public LinkedList<MessageEntry> getLogs() {
        return log;
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
        private MessageEntry messageEntry;
        private final ExecutorService executorService;
        private int lastSelectedIndex = -1;
        private final HttpRequestEditor requestEditor;
        private final HttpResponseEditor responseEditor;

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
            messageEntry = filteredLog.get(lastSelectedIndex);

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
