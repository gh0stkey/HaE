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
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class RequestEditor implements HttpRequestEditorProvider {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;

    public RequestEditor(MontoyaApi api, ConfigLoader configLoader) {
        this.api = api;
        this.configLoader = configLoader;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
        return new Editor(api, configLoader, editorCreationContext);
    }

    private static class Editor implements ExtensionProvidedHttpRequestEditor {
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
        public HttpRequest getRequest() {
            return requestResponse.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            generateTabbedPaneFromResultMap(api, jTabbedPane, this.dataList);
        }

        @Override
        public synchronized boolean isEnabledFor(HttpRequestResponse requestResponse) {
            HttpRequest request = requestResponse.request();
            if (request != null) {
                try {
                    String host = StringProcessor.getHostByUrl(request.url());
                    if (!host.isEmpty()) {
                        String[] hostList = configLoader.getBlockHost().split("\\|");
                        boolean isBlockHost = isBlockHost(hostList, host);

                        List<String> suffixList = Arrays.asList(configLoader.getExcludeSuffix().split("\\|"));
                        boolean matches = suffixList.contains(request.fileExtension().toLowerCase()) || isBlockHost;

                        if (!matches && !request.bodyToString().equals("Loading...")) {
                            this.dataList = messageProcessor.processRequest("", request, false);
                            return isListHasData(this.dataList);
                        }
                    }
                } catch (Exception ignored) {
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

    public static boolean isBlockHost(String[] hostList, String host) {
        boolean isBlockHost = false;
        for (String hostName : hostList) {
            String cleanedHost = StringProcessor.replaceFirstOccurrence(hostName, "*.", "");
            if (hostName.contains("*.") && StringProcessor.matchFromEnd(host, cleanedHost)) {
                isBlockHost = true;
            } else if (host.equals(hostName) || hostName.equals("*")) {
                isBlockHost = true;
            }
        }
        return isBlockHost;
    }

    public static boolean isListHasData(List<Map<String, String>> dataList) {
        if (dataList != null && !dataList.isEmpty()) {
            Map<String, String> dataMap = dataList.get(0);
            return dataMap != null && !dataMap.isEmpty();
        }
        return false;
    }

    public static void generateTabbedPaneFromResultMap(MontoyaApi api, JTabbedPane tabbedPane, List<Map<String, String>> result) {
        tabbedPane.removeAll();
        if (result != null && !result.isEmpty()) {
            Map<String, String> dataMap = result.get(0);
            if (dataMap != null && !dataMap.isEmpty()) {
                dataMap.keySet().forEach(i -> {
                    String[] extractData = dataMap.get(i).split("\n");
                    Datatable dataPanel = new Datatable(api, i, Arrays.asList(extractData));
                    tabbedPane.addTab(i, dataPanel);
                });
            }
        }
    }
}
