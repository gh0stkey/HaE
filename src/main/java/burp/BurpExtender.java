package burp;

import burp.action.*;
import burp.ui.MainUI;

import javax.swing.*;
import java.awt.*;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;
import java.io.PrintWriter;
import java.util.Map;

/*
 * @author EvilChen
 */

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory, ITab {
    private MainUI main = new MainUI();
    private static PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static IMessageEditorTab HaETab;
    MatchHTTP mh = new MatchHTTP();
    ExtractContent ec = new ExtractContent();
    DoAction da = new DoAction();
    GetColorKey gck = new GetColorKey();
    UpgradeColor uc = new UpgradeColor();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        String version = "2.0.2";
        callbacks.setExtensionName(String.format("HaE (%s) - Highlighter and Extractor", version));
        // 定义输出
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("@UI Author: 0chencc");
        stdout.println("@Core Author: EvilChen");
        stdout.println("@Github: https://github.com/gh0stkey/HaE");
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

    /*
     * 使用processHttpMessage用来做Highlighter
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 判断是否是响应，且该代码作用域为：REPEATER、INTRUDER、PROXY（分别对应toolFlag 64、32、4）
        if (toolFlag == 64 || toolFlag == 32 || toolFlag == 4) {
            Map<String, Map<String, Object>> obj;
            byte[] content = messageInfo.getRequest();
            // 获取报文头
            List<String> tmpHeaders = helpers.analyzeRequest(messageInfo.getHttpService(), content).getHeaders();
            String headers = String.join("\n", tmpHeaders);

            // 获取报文主体
            int bodyOffset = helpers.analyzeRequest(messageInfo.getHttpService(), content).getBodyOffset();
            byte[] byteRequest = messageInfo.getRequest();
            byte[] body = Arrays.copyOfRange(byteRequest, bodyOffset, byteRequest.length);

            // 流量清洗
            String urlString = helpers.analyzeRequest(messageInfo.getHttpService(), content).getUrl().toString();
            urlString = urlString.indexOf("?") > 0 ? urlString.substring(0, urlString.indexOf("?")) : urlString;

            // 正则判断
            if (mh.matchSuffix(urlString)) {
                return;
            }

            if (messageIsRequest) {
                obj = ec.matchRegex(content, headers, body, "request");
            } else {
                content = messageInfo.getResponse();
                obj = ec.matchRegex(content, headers, body, "response");
            }

            List<String> colorList = da.highlightList(obj);
            if (colorList.size() != 0) {
                String color = uc.getEndColor(gck.getColorKeys(colorList, Config.colorArray), Config.colorArray);
                messageInfo.setHighlight(color);
            }
        }

    }

    class MarkInfoTab implements IMessageEditorTab {
        private ITextEditor markInfoText;
        private byte[] currentMessage;
        private final IMessageEditorController controller;
        private byte[] extractRequestContent;
        private byte[] extractResponseContent;

        public MarkInfoTab(IMessageEditorController controller, boolean editable) {
            this.controller = controller;
            markInfoText = callbacks.createTextEditor();
            markInfoText.setEditable(editable);
        }

        @Override
        public String getTabCaption() {
            return "MarkInfo";
        }

        @Override
        public Component getUiComponent() {
            return markInfoText.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            Map<String, Map<String, Object>> obj;

            if (isRequest) {
                try {
                    // 流量清洗
                    String urlString = helpers.analyzeRequest(controller.getHttpService(), controller.getRequest()).getUrl().toString();
                    urlString = urlString.indexOf("?") > 0 ? urlString.substring(0, urlString.indexOf("?")) : urlString;
                    // 正则判断
                    if (mh.matchSuffix(urlString)) {
                        return false;
                    }
                } catch (Exception e) {
                    return false;
                }

                // 获取报文头
                List<String> tmpHeaders = helpers.analyzeRequest(controller.getHttpService(), content).getHeaders();
                String headers = String.join("\n", tmpHeaders);
                // 获取报文主体
                int bodyOffset = helpers.analyzeRequest(controller.getHttpService(), content).getBodyOffset();
                byte[] byteRequest = controller.getRequest();
                byte[] body = Arrays.copyOfRange(byteRequest, bodyOffset, byteRequest.length);

                obj = ec.matchRegex(content, headers, body, "request");
                if (obj.size() > 0) {
                    String result = da.extractString(obj);
                    extractRequestContent = result.getBytes();
                    return true;
                }
            } else {

                // 获取报文头
                List<String> tmpHeaders1 = helpers.analyzeResponse(content).getHeaders();
                String headers1 = String.join("\n", tmpHeaders1);
                // 获取报文主体
                int bodyOffset1 = helpers.analyzeResponse(content).getBodyOffset();
                byte[] byteRequest1 = controller.getResponse();
                byte[] body = Arrays.copyOfRange(byteRequest1, bodyOffset1, byteRequest1.length);

                obj = ec.matchRegex(content, headers1, body, "response");
                if (obj.size() > 0) {
                    String result = da.extractString(obj);
                    extractResponseContent = result.getBytes();
                    return true;
                }
            }
            return false;
        }

        @Override
        public byte[] getMessage() {
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return markInfoText.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return markInfoText.getSelectedText();
        }

        /*
         * 使用setMessage用来做Extractor
         */
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            try {
                String c = new String(content, "UTF-8").intern();
            } catch (UnsupportedEncodingException e) {
                stdout.println(e);
            }
            if (content.length > 0) {
                if (isRequest) {
                    markInfoText.setText(extractRequestContent);
                } else {
                    markInfoText.setText(extractResponseContent);
                }
            }
            currentMessage = content;
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        HaETab = new MarkInfoTab(controller, editable);
        return HaETab;
    }
}