package burp;

import burp.action.*;
import burp.ui.MainUI;

import java.util.Map;
import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * @author EvilChen & 0chencc
 */

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory, ITab {
    private final MainUI main = new MainUI();
    private static PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    GetColorKey gck = new GetColorKey();
    UpgradeColor uc = new UpgradeColor();
    ProcessMessage pm = new ProcessMessage();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        String version = "2.2.3";
        callbacks.setExtensionName(String.format("HaE (%s) - Highlighter and Extractor", version));
        // 定义输出
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("@Core Author: EvilChen");
        stdout.println("@Architecture Author: 0chencc");
        stdout.println("@Github: https://github.com/gh0stkey/HaE");
        // UI
        SwingUtilities.invokeLater(this::initialize);

        callbacks.registerHttpListener(BurpExtender.this);
        callbacks.registerMessageEditorTabFactory(BurpExtender.this);
    }

    private void initialize(){
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(BurpExtender.this);
    }

    @Override
    public String getTabCaption(){
        return "HaE";
    }

    @Override
    public Component getUiComponent() {
        return main;
    }

    /**
     * 使用processHttpMessage用来做Highlighter
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 判断是否是响应，且该代码作用域为：REPEATER、INTRUDER、PROXY（分别对应toolFlag 64、32、4）
        if (toolFlag == 64 || toolFlag == 32 || toolFlag == 4) {
            byte[] content;
            if (messageIsRequest) {
                content = messageInfo.getRequest();
            } else {
                content = messageInfo.getResponse();
            }

            String c = new String(content, StandardCharsets.UTF_8).intern();
            List<Map<String, String>> result = pm.processMessageByContent(helpers, content, messageIsRequest, true);
            if (result != null && !result.isEmpty() && result.size() > 0) {
                String originalColor = messageInfo.getHighlight();
                String originalComment = messageInfo.getComment();
                List<String> colorList = new ArrayList<>();
                if (originalColor != null) {
                    colorList.add(originalColor);
                }
                colorList.add(result.get(0).get("color"));
                String color = uc.getEndColor(gck.getColorKeys(colorList));

                messageInfo.setHighlight(color);
                String addComment = String.join(", ", result.get(1).get("comment"));
                String resComment = originalComment != null ? String.format("%s, %s", originalComment, addComment) : addComment;

                messageInfo.setComment(resComment);
            }
        }
    }

    class MarkInfoTab implements IMessageEditorTab {
        private final JTabbedPane jTabbedPane = new JTabbedPane();
        private JTable jTable = new JTable();
        private final IMessageEditorController controller;
        private Map<String, String> extractRequestMap;
        private Map<String, String> extractResponseMap;

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
                    jTable = (JTable) ((JScrollPane)jTabbedPane.getSelectedComponent()).getViewport().getView();
                }
            });
            return this.jTabbedPane;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            String c = new String(content, StandardCharsets.UTF_8).intern();
            List<Map<String, String>> result = pm.processMessageByContent(helpers, content, isRequest, false);
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
            int[] selectRows = jTable.getSelectedRows();
            StringBuilder selectData = new StringBuilder();
            for (int row : selectRows) {
                selectData.append(jTable.getValueAt(row, 0).toString()).append("\n");
            }
            // 便于单行复制，去除最后一个换行符
            String revData = selectData.reverse().toString().replaceFirst("\n", "");
            StringBuilder retData = new StringBuilder(revData).reverse();
            return helpers.stringToBytes(retData.toString());
        }

        /**
         * 使用setMessage用来做Extractor
         */
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            String c = new String(content, StandardCharsets.UTF_8).intern();
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
            dataMap.keySet().forEach(i->{
                String[] extractData = dataMap.get(i).split("\n");
                Object[][] data = new Object[extractData.length][1];
                for (int x = 0; x < extractData.length; x++) {
                    data[x][0] = extractData[x];
                }
                int indexOfTab = this.jTabbedPane.indexOfTab(i);
                JScrollPane jScrollPane = new JScrollPane(new JTable(data, new Object[] {"Information"}));
                this.jTabbedPane.addTab(i, jScrollPane);
                // 使用removeAll会导致UI出现空白的情况，为了改善用户侧体验，采用remove的方式进行删除
                if (indexOfTab != -1) {
                    this.jTabbedPane.remove(indexOfTab);
                }
            });
        }
    }



    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new MarkInfoTab(controller, editable);
    }
}