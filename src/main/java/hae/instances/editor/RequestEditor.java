package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
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

        private final JTabbedPane jTabbedPane = new JTabbedPane();

        public Editor(MontoyaApi api, EditorCreationContext creationContext) {
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
                generateTabbedPaneFromResultMap(api, jTabbedPane, result);
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
                    Datatable dataTable = (Datatable) jTabbedPane.getSelectedComponent();
                    return ByteArray.byteArray(dataTable.getSelectedDataAtTable(dataTable.getDataTable()));
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

    public static void generateTabbedPaneFromResultMap(MontoyaApi api, JTabbedPane tabbedPane, List<Map<String, String>> result) {
        tabbedPane.removeAll();
        if (result != null && !result.isEmpty() && result.size() > 0) {
            Map<String, String> dataMap = result.get(0);
            if (dataMap != null && !dataMap.isEmpty() && dataMap.size() > 0) {
                dataMap.keySet().forEach(i -> {
                    String[] extractData = dataMap.get(i).split("\n");
                    Datatable dataPanel = new Datatable(api, i, Arrays.asList(extractData));
                    tabbedPane.addTab(i, dataPanel);
                });
            }
        }
    }
}
