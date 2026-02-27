package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import hae.component.board.table.Datatable;
import hae.instances.http.utils.MessageProcessor;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;

public class WebSocketEditor implements WebSocketMessageEditorProvider {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final DataRepository dataRepository;
    private final RuleRepository ruleRepository;
    private final ValidatorService validatorService;

    public WebSocketEditor(MontoyaApi api, ConfigLoader configLoader,
                           DataRepository dataRepository, RuleRepository ruleRepository,
                           ValidatorService validatorService) {
        this.api = api;
        this.configLoader = configLoader;
        this.dataRepository = dataRepository;
        this.ruleRepository = ruleRepository;
        this.validatorService = validatorService;
    }

    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext editorCreationContext) {
        return new Editor(api, configLoader, dataRepository, ruleRepository, validatorService, editorCreationContext);
    }

    private static class Editor implements ExtensionProvidedWebSocketMessageEditor {
        private final MontoyaApi api;
        private final ConfigLoader configLoader;
        private final EditorCreationContext creationContext;
        private final MessageProcessor messageProcessor;
        private final ValidatorService validatorService;
        private final JTabbedPane jTabbedPane = new JTabbedPane();
        private ByteArray message;
        private List<Map<String, String>> dataList;

        public Editor(MontoyaApi api, ConfigLoader configLoader,
                      DataRepository dataRepository, RuleRepository ruleRepository,
                      ValidatorService validatorService, EditorCreationContext creationContext) {
            this.api = api;
            this.configLoader = configLoader;
            this.creationContext = creationContext;
            this.messageProcessor = new MessageProcessor(api, configLoader, dataRepository, ruleRepository);
            this.validatorService = validatorService;
        }

        @Override
        public ByteArray getMessage() {
            return message;
        }

        @Override
        public void setMessage(WebSocketMessage webSocketMessage) {
            this.message = webSocketMessage.payload();
            EditorUtils.generateTabbedPaneFromResultMap(api, configLoader, jTabbedPane, this.dataList, validatorService);
        }

        @Override
        public boolean isEnabledFor(WebSocketMessage webSocketMessage) {
            String websocketMessage = webSocketMessage.payload().toString();
            if (!websocketMessage.isEmpty()) {
                String url = webSocketMessage.upgradeRequest().url();
                String host = StringProcessor.getHostByUrl(url);
                this.dataList = messageProcessor.processMessage(host, url, websocketMessage, false);
                return EditorUtils.isListHasData(this.dataList);
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
