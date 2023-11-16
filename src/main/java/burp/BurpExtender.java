package burp;

import burp.config.ConfigLoader;
import burp.core.processor.ColorProcessor;
import burp.core.processor.MessageProcessor;
import burp.ui.MainUI;
import burp.ui.board.DatatablePanel;
import burp.ui.board.MessagePanel;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;
import java.util.*;
import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.List;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * @author EvilChen & 0chencc
 */

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory, ITab {
    private MainUI main;
    public static PrintWriter stdout;
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    ColorProcessor colorProcessor = new ColorProcessor();
    MessageProcessor messageProcessor = new MessageProcessor();
    private MessagePanel messagePanel;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        new ConfigLoader();

        String version = "2.5.8";
        callbacks.setExtensionName(String.format("HaE (%s) - Highlighter and Extractor", version));

        // 定义输出
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("[ HACK THE WORLD - TO DO IT ]");
        stdout.println("[#] Author: EvilChen & 0chencc");
        stdout.println("[#] Github: https://github.com/gh0stkey/HaE");

        // UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                initialize();
            }
        });

        callbacks.registerHttpListener(BurpExtender.this);
        callbacks.registerMessageEditorTabFactory(BurpExtender.this);

    }

    private void initialize() {
        messagePanel = new MessagePanel(callbacks, helpers);
        main = new MainUI(messagePanel);
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(BurpExtender.this);
    }

    @Override
    public String getTabCaption() {
        return "HaE";
    }

    @Override
    public Component getUiComponent() {
        JTabbedPane HaETabbedPane = new JTabbedPane();
        HaETabbedPane.addTab("", getImageIcon(false), main);
        HaETabbedPane.addTab(" Highlighter and Extractor - Empower ethical hacker for efficient operations ", null);
        HaETabbedPane.setEnabledAt(1, false);
        HaETabbedPane.addPropertyChangeListener("background", new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent e) {
                boolean isDarkBg = isDarkBg();
                HaETabbedPane.setIconAt(0, getImageIcon(isDarkBg));
            }

            private boolean isDarkBg() {
                Color bg = HaETabbedPane.getBackground();
                int r = bg.getRed();
                int g = bg.getGreen();
                int b = bg.getBlue();
                int avg = (r + g + b) / 3;

                return avg < 128;
            }
        });
        return HaETabbedPane;
    }

    private ImageIcon getImageIcon(boolean isDark) {
        ClassLoader classLoader = getClass().getClassLoader();
        URL imageURL;
        if (isDark) {
            imageURL = classLoader.getResource("logo.png");
        } else {
            imageURL = classLoader.getResource("logo_black.png");
        }
        ImageIcon originalIcon = new ImageIcon(imageURL);
        Image originalImage = originalIcon.getImage();
        Image scaledImage = originalImage.getScaledInstance(30, 20, Image.SCALE_FAST);
        ImageIcon scaledIcon = new ImageIcon(scaledImage);
        return scaledIcon;
    }

    /**
     * 使用processHttpMessage用来做Highlighter
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 判断是否是响应，且该代码作用域为：REPEATER、INTRUDER、PROXY（分别对应toolFlag 64、32、4）
        if (toolFlag == 64 || toolFlag == 32 || toolFlag == 4) {
            if (!messageIsRequest) {
                IHttpService iHttpService = messageInfo.getHttpService();
                String host = iHttpService.getHost();

                List<Map<String, String>> result = null;

                String originalColor = messageInfo.getHighlight();
                String originalComment = messageInfo.getComment();

                try {
                    result = messageProcessor.processMessage(helpers, messageInfo, host, true);

                    if (result != null && !result.isEmpty() && result.size() > 0) {
                        List<String> colorList = new ArrayList<>();

                        if (originalColor != null) {
                            colorList.add(originalColor);
                        }

                        colorList.add(result.get(0).get("color"));
                        String resColor = colorProcessor.retrieveFinalColor(colorProcessor.retrieveColorIndices(colorList));
                        messageInfo.setHighlight(resColor);

                        String addComment = String.join(", ", result.get(1).get("comment"));
                        String allComment = !Objects.equals(originalComment, "") ? String.format("%s, %s", originalComment, addComment) : addComment;
                        String resComment = mergeComment(allComment);
                        messageInfo.setComment(resComment);

                        messagePanel.add(messageInfo, resComment, resColor);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        }
    }

    private String mergeComment(String comment) {
        if (!comment.contains(",")) {
            return comment;
        }

        Map<String, Integer> itemCounts = new HashMap<>();
        String[] items = comment.split(", ");

        for (String item : items) {
            if (item.contains("(") && item.contains(")")) {
                int openParenIndex = item.lastIndexOf("(");
                int closeParenIndex = item.lastIndexOf(")");
                String itemName = item.substring(0, openParenIndex).trim();
                int count = Integer.parseInt(item.substring(openParenIndex + 1, closeParenIndex).trim());
                itemCounts.put(itemName, itemCounts.getOrDefault(itemName, 0) + count);
            } else {
                itemCounts.put(item, 0);
            }
        }

        StringBuilder mergedItems = new StringBuilder();

        for (Map.Entry<String, Integer> entry : itemCounts.entrySet()) {
            String itemName = entry.getKey();
            int count = entry.getValue();
            if (count != 0) {
                mergedItems.append(itemName).append(" (").append(count).append("), ");
            }
        }

        return mergedItems.substring(0, mergedItems.length() - 2);
    }

    class MarkInfoTab implements IMessageEditorTab {
        private final JTabbedPane jTabbedPane = new JTabbedPane();
        private DatatablePanel dataPanel;
        private JTable dataTable;
        private final IMessageEditorController controller;
        private Map<String, String> extractRequestMap;
        private Map<String, String> extractResponseMap;
        private ArrayList<String> titleList = new ArrayList<>();

        public MarkInfoTab(IMessageEditorController controller, boolean editable) {
            this.controller = controller;
        }

        @Override
        public String getTabCaption() {
            return "MarkInfo";
        }

        @Override
        public Component getUiComponent() {
            jTabbedPane.addChangeListener(new ChangeListener() {
                @Override
                public void stateChanged(ChangeEvent arg0) {
                    dataTable = ((DatatablePanel)jTabbedPane.getSelectedComponent()).getTable();
                }
            });
            return jTabbedPane;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            List<Map<String, String>> result = null;

            try {
                if (isRequest) {
                    result = messageProcessor.processRequestMessage(helpers, content, "", false);
                } else {
                    result = messageProcessor.processResponseMessage(helpers, content, "", false);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (result != null && !result.isEmpty()) {
                Map<String, String> dataMap = result.get(0);
                if (isRequest) {
                    extractRequestMap = dataMap;
                } else {
                    extractResponseMap = dataMap;
                }
                return true;
            }

            return false;
        }

        @Override
        public byte[] getMessage() {
            return null;
        }

        @Override
        public boolean isModified() {
            return false;
        }

        /**
         * 快捷键复制功能
         */
        @Override
        public byte[] getSelectedData() {
            return helpers.stringToBytes(dataPanel.getSelectedData(dataTable));
        }

        /**
         * 使用setMessage用来做Extractor
         */
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content.length > 0) {
                if (isRequest) {
                    makeTable(extractRequestMap);
                } else {
                    makeTable(extractResponseMap);
                }
            }
        }

        /**
         * 创建MarkInfo表单
         */
        public void makeTable(Map<String, String> dataMap) {
            ArrayList<String> lTitleList = new ArrayList<>();

            dataMap.keySet().forEach(i->{
                String[] extractData = dataMap.get(i).split("\n");
                lTitleList.add(i);
                dataPanel = new DatatablePanel(i, Arrays.asList(extractData));
                jTabbedPane.addTab(i, dataPanel);
            });

            /*
             * 使用removeAll会导致MarkInfo UI出现空白的情况，为了改善用户侧体验，采用remove的方式进行删除；
             * 采用全局ArrayList的方式遍历删除Tab，以此应对BurpSuite缓存机制导致的MarkInfo UI错误展示。
             */
            titleList.forEach(t->{
                int indexOfTab = jTabbedPane.indexOfTab(t);
                if (indexOfTab != -1) {
                    jTabbedPane.removeTabAt(indexOfTab);
                }
            });

            titleList = lTitleList;
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new MarkInfoTab(controller, editable);
    }
}
