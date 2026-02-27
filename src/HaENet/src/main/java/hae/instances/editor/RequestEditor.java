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
import hae.component.board.table.Datatable;
import hae.instances.http.utils.MessageProcessor;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.http.HttpUtils;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;

public class RequestEditor implements HttpRequestEditorProvider {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final DataRepository dataRepository;
    private final RuleRepository ruleRepository;
    private final ValidatorService validatorService;

    public RequestEditor(MontoyaApi api, ConfigLoader configLoader,
                         DataRepository dataRepository, RuleRepository ruleRepository,
                         ValidatorService validatorService) {
        this.api = api;
        this.configLoader = configLoader;
        this.dataRepository = dataRepository;
        this.ruleRepository = ruleRepository;
        this.validatorService = validatorService;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext editorCreationContext) {
        return new Editor(api, configLoader, dataRepository, ruleRepository, validatorService, editorCreationContext);
    }

    private static class Editor implements ExtensionProvidedHttpRequestEditor {
        private final MontoyaApi api;
        private final ConfigLoader configLoader;
        private final HttpUtils httpUtils;
        private final EditorCreationContext creationContext;
        private final MessageProcessor messageProcessor;
        private final ValidatorService validatorService;
        private final JTabbedPane jTabbedPane = new JTabbedPane();
        private HttpRequestResponse requestResponse;
        private List<Map<String, String>> dataList;

        public Editor(MontoyaApi api, ConfigLoader configLoader,
                      DataRepository dataRepository, RuleRepository ruleRepository,
                      ValidatorService validatorService, EditorCreationContext creationContext) {
            this.api = api;
            this.configLoader = configLoader;
            this.httpUtils = new HttpUtils(api, configLoader);
            this.creationContext = creationContext;
            this.messageProcessor = new MessageProcessor(api, configLoader, dataRepository, ruleRepository);
            this.validatorService = validatorService;
        }

        @Override
        public HttpRequest getRequest() {
            return requestResponse.request();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
            EditorUtils.generateTabbedPaneFromResultMap(api, configLoader, jTabbedPane, this.dataList, validatorService);
        }

        @Override
        public synchronized boolean isEnabledFor(HttpRequestResponse requestResponse) {
            HttpRequest request = requestResponse.request();
            if (request != null) {
                try {
                    String url = request.url();
                    String host = StringProcessor.getHostByUrl(url);
                    if (!host.isEmpty()) {
                        String toolType = creationContext.toolSource().toolType().toolName();
                        boolean matches = httpUtils.verifyHttpRequestResponse(requestResponse, toolType);

                        if (!matches) {
                            this.dataList = messageProcessor.processRequest(host, url, request, false);
                            return EditorUtils.isListHasData(this.dataList);
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
}
