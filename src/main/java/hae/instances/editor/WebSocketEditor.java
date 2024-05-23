package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;
import hae.component.board.Datatable;
import hae.instances.http.utils.MessageProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;

public class WebSocketEditor implements WebSocketMessageEditorProvider {
    private final MontoyaApi api;

    public WebSocketEditor(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext editorCreationContext) {
        return new Editor(api, editorCreationContext);
    }

    private static class Editor implements ExtensionProvidedWebSocketMessageEditor {
        private final MontoyaApi api;
        private final EditorCreationContext creationContext;
        private final MessageProcessor messageProcessor;
        private ByteArray message;
        private List<Map<String, String>> dataList;

        private final JTabbedPane jTabbedPane = new JTabbedPane();

        public Editor(MontoyaApi api, EditorCreationContext creationContext) {
            this.api = api;
            this.creationContext = creationContext;
            this.messageProcessor = new MessageProcessor(api);
        }

        @Override
        public ByteArray getMessage() {
            return message;
        }

        @Override
        public void setMessage(WebSocketMessage webSocketMessage) {
            this.message = webSocketMessage.payload();
            RequestEditor.generateTabbedPaneFromResultMap(api, jTabbedPane, this.dataList);
        }

        @Override
        public boolean isEnabledFor(WebSocketMessage webSocketMessage) {
            String websocketMessage = webSocketMessage.payload().toString();
            if (!websocketMessage.isEmpty()) {
                this.dataList = messageProcessor.processMessage("", websocketMessage, false);
                return RequestEditor.isListHasData(this.dataList);
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
