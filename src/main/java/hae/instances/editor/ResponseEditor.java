package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import hae.component.board.table.Datatable;
import hae.instances.http.utils.MessageProcessor;
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class ResponseEditor implements HttpResponseEditorProvider {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;

    public ResponseEditor(MontoyaApi api, ConfigLoader configLoader) {
        this.api = api;
        this.configLoader = configLoader;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
        return new Editor(api, configLoader, editorCreationContext);
    }

    private static class Editor implements ExtensionProvidedHttpResponseEditor {
        private final MontoyaApi api;
        private final ConfigLoader configLoader;
        private final EditorCreationContext creationContext;
        private final MessageProcessor messageProcessor;
        private HttpRequestResponse requestResponse;
        private List<Map<String, String>> dataList;

        private final JTabbedPane jTabbedPane = new JTabbedPane();

        public Editor(MontoyaApi api, ConfigLoader configLoader, EditorCreationContext creationContext) {
            this.api = api;
            this.configLoader = configLoader;
            this.creationContext = creationContext;
            this.messageProcessor = new MessageProcessor(api);
        }

        @Override
        public HttpResponse getResponse() {
            return requestResponse.response();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            RequestEditor.generateTabbedPaneFromResultMap(api, configLoader, jTabbedPane, this.dataList);
        }

        @Override
        public synchronized boolean isEnabledFor(HttpRequestResponse requestResponse) {
            HttpResponse response = requestResponse.response();

            if (response != null) {
                HttpRequest request = requestResponse.request();
                boolean matches = false;

                if (request != null) {
                    try {
                        String host = StringProcessor.getHostByUrl(request.url());
                        if (!host.isEmpty()) {
                            String[] hostList = configLoader.getBlockHost().split("\\|");
                            boolean isBlockHost = RequestEditor.isBlockHost(hostList, host);

                            List<String> suffixList = Arrays.asList(configLoader.getExcludeSuffix().split("\\|"));
                            String toolType = creationContext.toolSource().toolType().toolName();
                            boolean isToolScope = configLoader.getScope().contains(toolType);

                            matches = suffixList.contains(request.fileExtension().toLowerCase()) || isBlockHost || !isToolScope;
                        }
                    } catch (Exception ignored) {
                    }
                }

                if (!matches && !response.bodyToString().equals("Loading...")) {
                    this.dataList = messageProcessor.processResponse("", response, false);
                    return RequestEditor.isListHasData(this.dataList);
                }
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
}
