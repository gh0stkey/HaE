package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import hae.component.board.Datatable;
import hae.instances.http.utils.MessageProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class RequestEditor implements HttpRequestEditorProvider {
    private final MontoyaApi api;

    public RequestEditor(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
        return new Editor(api, editorCreationContext);
    }

    private static class Editor implements ExtensionProvidedHttpRequestEditor {
        private final MontoyaApi api;
        private final EditorCreationContext creationContext;
        private final MessageProcessor messageProcessor;
        private HttpRequestResponse requestResponse;

        private JTabbedPane jTabbedPane = new JTabbedPane();

        public Editor(MontoyaApi api, EditorCreationContext creationContext)
        {
            this.api = api;
            this.creationContext = creationContext;
            this.messageProcessor = new MessageProcessor(api);
        }

        @Override
        public HttpRequest getRequest() {
            return requestResponse.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
        }

        @Override
        public synchronized boolean isEnabledFor(HttpRequestResponse requestResponse) {
            HttpRequest request = requestResponse.request();
            if (request != null && !request.bodyToString().equals("Loading...")) {
                List<Map<String, String>> result = messageProcessor.processRequest("", request, false);
                jTabbedPane = generateTabbedPaneFromResultMap(api, result);
                return jTabbedPane.getTabCount() > 0;
            }
            return false;
        }

        @Override
        public String caption() {
            return "MarkInfo";
        }

        @Override
        public Component uiComponent() {
            return jTabbedPane;
        }

        @Override
        public Selection selectedData() {
            return new Selection() {
                @Override
                public ByteArray contents() {
                    return ByteArray.byteArray(Datatable.getSelectedData(((Datatable) jTabbedPane.getSelectedComponent()).getDataTable()));
                }

                @Override
                public Range offsets() {
                    return null;
                }
            };
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }

    public static JTabbedPane generateTabbedPaneFromResultMap(MontoyaApi api, List<Map<String, String>> result) {
        JTabbedPane tabbedPane = new JTabbedPane();
        if (result != null && !result.isEmpty() && result.size() > 0) {
            Map<String, String> dataMap = result.get(0);
            if (dataMap != null && !dataMap.isEmpty() && dataMap.size() > 0) {
                dataMap.keySet().forEach(i->{
                    String[] extractData = dataMap.get(i).split("\n");
                    Datatable dataPanel = new Datatable(api, i, Arrays.asList(extractData));
                    tabbedPane.addTab(i, dataPanel);
                });
            }
        }

        return tabbedPane;
    }
}
