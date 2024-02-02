package burp.ui.board;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.config.ConfigEntry;
import burp.core.GlobalCachePool;
import burp.core.utils.HashCalculator;
import burp.core.utils.StringHelper;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

/**
 * @author EvilChen
 */

public class MessagePanel extends AbstractTableModel implements IMessageEditorController {
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final IBurpExtenderCallbacks callbacks;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private final List<LogEntry> filteredLog = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private final IExtensionHelpers helpers;
    private final Table logTable;

    public MessagePanel(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;

        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        logTable = new Table(MessagePanel.this);
        logTable.setDefaultRenderer(Object.class, new ColorRenderer(filteredLog, logTable));
        logTable.setAutoCreateRowSorter(true);

        // Length字段根据大小进行排序
        TableRowSorter<DefaultTableModel> sorter = (TableRowSorter<DefaultTableModel>) logTable.getRowSorter();
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
                for (int i = 0; i < ConfigEntry.colorArray.length; i++) {
                    if (ConfigEntry.colorArray[i].equals(color)) {
                        return i;
                    }
                }
                return -1;
            }
        });

        logTable.setRowSorter(sorter);
        logTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        JScrollPane scrollPane = new JScrollPane(logTable);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        splitPane.setLeftComponent(scrollPane);

        JTabbedPane tabs = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(MessagePanel.this, false);

        responseViewer = callbacks.createMessageEditor(MessagePanel.this, false);
        tabs.addTab("Request", requestViewer.getComponent());
        tabs.addTab("Response", responseViewer.getComponent());
        splitPane.setRightComponent(tabs);
    }

    public JSplitPane getPanel() {
        return splitPane;
    }

    public Table getTable() {
        return logTable;
    }

    public List<LogEntry> getLogs() {
        return log;
    }

    @Override
    public int getRowCount()
    {
        return filteredLog.size();
    }

    @Override
    public int getColumnCount()
    {
        return 6;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "Method";
            case 1:
                return "URL";
            case 2:
                return "Comment";
            case 3:
                return "Status";
            case 4:
                return "Length";
            case 5:
                return "Color";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        if (filteredLog.isEmpty()) {
            return "";
        }
        LogEntry logEntry = filteredLog.get(rowIndex);
        switch (columnIndex)
        {
            case 0:
                return logEntry.getMethod();
            case 1:
                return logEntry.getUrl().toString();
            case 2:
                return logEntry.getComment();
            case 3:
                return logEntry.getStatus();
            case 4:
                return logEntry.getLength();
            case 5:
                return logEntry.getColor();
            default:
                return "";
        }
    }

    public void applyHostFilter(String filterText) {
        filteredLog.clear();
        fireTableDataChanged();
        String cleanedText = StringHelper.replaceFirstOccurrence(filterText, "*.", "");

        for (LogEntry entry : log) {
            String host = entry.getUrl().getHost();
            if (filterText.contains("*.") && StringHelper.matchFromEnd(host, cleanedText)) {
                filteredLog.add(entry);
            } else if (host.equals(filterText) || filterText.contains("*")) {
                filteredLog.add(entry);
            }
        }
        fireTableDataChanged();
    }

    public void applyMessageFilter(String tableName, String filterText) {
        filteredLog.clear();
        for (LogEntry entry : log) {
            IHttpRequestResponsePersisted requestResponse = entry.getRequestResponse();
            byte[] requestByte = requestResponse.getRequest();
            byte[] responseByte = requestResponse.getResponse();

            String requestString = new String(requestResponse.getRequest(), StandardCharsets.UTF_8);
            String responseString = new String(requestResponse.getResponse(), StandardCharsets.UTF_8);

            List<String> requestTmpHeaders = helpers.analyzeRequest(requestByte).getHeaders();
            String requestHeaders = new String(String.join("\n", requestTmpHeaders).getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
            int requestBodyOffset = helpers.analyzeRequest(requestByte).getBodyOffset();
            String requestBody = new String(Arrays.copyOfRange(requestByte, requestBodyOffset, requestByte.length), StandardCharsets.UTF_8);

            List<String> responseTmpHeaders = helpers.analyzeResponse(responseByte).getHeaders();
            String responseHeaders = new String(String.join("\n", responseTmpHeaders).getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
            int responseBodyOffset = helpers.analyzeResponse(responseByte).getBodyOffset();
            String responseBody = new String(Arrays.copyOfRange(responseByte, responseBodyOffset, responseByte.length), StandardCharsets.UTF_8);

            // 标志变量，表示是否满足过滤条件
            AtomicBoolean isMatched = new AtomicBoolean(false);

            ConfigEntry.globalRules.keySet().forEach(i -> {
                for (Object[] objects : ConfigEntry.globalRules.get(i)) {
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
        logTable.lastSelectedIndex = -1;
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

    public void deleteByHost(String filterText) {
        filteredLog.clear();
        List<Integer> rowsToRemove = new ArrayList<>();
        for (int i = 0; i < log.size(); i++) {
            LogEntry entry = log.get(i);
            String host = entry.getUrl().getHost();
            if (StringHelper.matchFromEnd(host, filterText) || filterText.contains("*")) {
                rowsToRemove.add(i);
            }
        }

        for (int i = rowsToRemove.size() - 1; i >= 0; i--) {
            int row = rowsToRemove.get(i);
            log.remove(row);
        }

        if (!rowsToRemove.isEmpty()) {
            int[] rows = rowsToRemove.stream().mapToInt(Integer::intValue).toArray();
            fireTableRowsDeleted(rows[0], rows[rows.length - 1]);
        }
    }

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    public void add(IHttpRequestResponse messageInfo, String comment, String color) {
        synchronized(log) {
            IRequestInfo iRequestInfo = helpers.analyzeRequest(messageInfo);
            URL url = iRequestInfo.getUrl();
            String method = iRequestInfo.getMethod();
            String status = String.valueOf(helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode());
            String length = String.valueOf(messageInfo.getResponse().length);
            LogEntry logEntry = new LogEntry(callbacks.saveBuffersToTempFiles(messageInfo), method, url, comment, length, color, status);

            try {
                // 比较Hash，如若存在重复的请求或响应，则不放入消息内容里
                byte[] reqByteA = messageInfo.getRequest();
                byte[] resByteA = messageInfo.getResponse();
                boolean isDuplicate = false;

                if (log.size() > 0) {
                    for (LogEntry entry : log) {
                        IHttpRequestResponsePersisted reqResMessage = entry.getRequestResponse();
                        byte[] reqByteB = reqResMessage.getRequest();
                        byte[] resByteB = reqResMessage.getResponse();
                        try {
                            // 通过URL、请求和响应报文、匹配数据内容，多维度进行对比
                            if ((entry.getUrl().toString().equals(url.toString()) || (Arrays.equals(reqByteB, reqByteA) || Arrays.equals(resByteB, resByteA))) && (areMapsEqual(getCacheData(reqByteB), getCacheData(reqByteA)) && areMapsEqual(getCacheData(resByteB), getCacheData(resByteA)))) {
                                isDuplicate = true;
                                break;
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }

                if (!isDuplicate) {
                    log.add(logEntry);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

    }

    private Map<String, Map<String, Object>> getCacheData(byte[] content)
            throws NoSuchAlgorithmException {
        String hashIndex = HashCalculator.calculateHash(content);
        return GlobalCachePool.getFromCache(hashIndex);
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
            if (!areInnerMapsEqual(map1.get(key), map2.get(key))) {
                return false;
            }
        }

        return true;
    }

    private boolean areInnerMapsEqual(Map<String, Object> innerMap1, Map<String, Object> innerMap2) {
        if (innerMap1.size() != innerMap2.size()) {
            return false;
        }

        for (String key : innerMap1.keySet()) {
            if (!innerMap2.containsKey(key)) {
                return false;
            }
            Object value1 = innerMap1.get(key);
            Object value2 = innerMap2.get(key);

            // 如果值是Map，则递归对比
            if (value1 instanceof Map && value2 instanceof Map) {
                if (!areInnerMapsEqual((Map<String, Object>) value1, (Map<String, Object>) value2)) {
                    return false;
                }
            } else if (!value1.equals(value2)) {
                return false;
            }
        }

        return true;
    }

    public class Table extends JTable {
        LogEntry logEntry;
        private SwingWorker<Object, Void> currentWorker;
        // 设置响应报文返回的最大长度为3MB
        private final int MAX_LENGTH = 3145728;
        private int lastSelectedIndex = -1;

        public Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            super.changeSelection(row, col, toggle, extend);
            int selectedIndex = convertRowIndexToModel(row);
            if (lastSelectedIndex != selectedIndex) {
                lastSelectedIndex = selectedIndex;
                logEntry = filteredLog.get(selectedIndex);

                requestViewer.setMessage("Loading...".getBytes(), true);
                responseViewer.setMessage("Loading...".getBytes(), false);
                currentlyDisplayedItem = logEntry.getRequestResponse();

                if (currentWorker != null && !currentWorker.isDone()) {
                    currentWorker.cancel(true);
                }

                currentWorker = new SwingWorker<Object, Void>() {
                    @Override
                    protected byte[][] doInBackground() throws Exception {
                        byte[] requestByte = logEntry.getRequestResponse().getRequest();
                        byte[] responseByte = logEntry.getRequestResponse().getResponse();

                        if (responseByte.length > MAX_LENGTH) {
                            String ellipsis = "\r\n......";
                            responseByte = Arrays.copyOf(responseByte, MAX_LENGTH + ellipsis.length());
                            byte[] ellipsisBytes = ellipsis.getBytes();
                            System.arraycopy(ellipsisBytes, 0, responseByte, MAX_LENGTH, ellipsisBytes.length);
                        }

                        return new byte[][] {requestByte, responseByte};
                    }

                    @Override
                    protected void done() {
                        if (!isCancelled()) {
                            try {
                                byte[][] result = (byte[][]) get();
                                requestViewer.setMessage(result[0], true);
                                responseViewer.setMessage(result[1], false);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                };
                currentWorker.execute();
            }
        }
    }

}