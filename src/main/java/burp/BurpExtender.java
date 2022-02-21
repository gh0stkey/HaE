package burp;

import burp.action.*;
import burp.ui.MainUI;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/*
 * @author EvilChen
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

        String version = "2.1.4";
        callbacks.setExtensionName(String.format("HaE (%s) - Highlighter and Extractor", version));
        // 定义输出
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("@Core Author: EvilChen");
        stdout.println("@Architecture Author: 0chencc");
        stdout.println("@Github: https://github.com/gh0stkey/HaE");
        stdout.println("@Team: OverSpace Security Team");
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

    /*
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
            List<String> result = pm.processMessageByContent(helpers, content, messageIsRequest, true);
            if (result != null && !result.isEmpty() && result.size() > 0) {
                String originalColor = messageInfo.getHighlight();
                String originalComment = messageInfo.getComment();
                List<String> colorList = new ArrayList<>();
                if (originalColor != null) {
                    colorList.add(originalColor);
                }
                colorList.add(result.get(0));
                String color = uc.getEndColor(gck.getColorKeys(colorList));

                messageInfo.setHighlight(color);
                String addComment = String.join(", ", result.get(1));
                String resComment = originalComment != null ? String.format("%s, %s", originalComment, addComment) : addComment;

                messageInfo.setComment(resComment);
            }
        }

    }


    class MarkInfoTab implements IMessageEditorTab {
        private final ITextEditor markInfoText;
        private byte[] currentMessage;
        private final IMessageEditorController controller;
        private byte[] extractRequestContent;
        private byte[] extractResponseContent;

        public MarkInfoTab(IMessageEditorController controller, boolean editable) {
            this.controller = controller;
            this.markInfoText = callbacks.createTextEditor();
            this.markInfoText.setEditable(editable);
        }

        @Override
        public String getTabCaption() {
            return "MarkInfo";
        }

        @Override
        public Component getUiComponent() {
            return this.markInfoText.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            String c = new String(content, StandardCharsets.UTF_8).intern();
            List<String> result = pm.processMessageByContent(helpers, content, isRequest, false);
            if (result != null && !result.isEmpty()) {
                if (isRequest) {
                    this.extractRequestContent = result.get(0).getBytes();
                } else {
                    this.extractResponseContent = result.get(0).getBytes();
                }
                return true;
            }
            return false;
        }

        @Override
        public byte[] getMessage() {
            return this.currentMessage;
        }

        @Override
        public boolean isModified() {
            return this.markInfoText.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return this.markInfoText.getSelectedText();
        }

        /*
         * 使用setMessage用来做Extractor
         */
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            String c = new String(content, StandardCharsets.UTF_8).intern();
            if (content.length > 0) {
                if (isRequest) {
                    this.markInfoText.setText(this.extractRequestContent);
                } else {
                    this.markInfoText.setText(this.extractResponseContent);
                }
            }
            this.currentMessage = content;
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new MarkInfoTab(controller, editable);
    }
}