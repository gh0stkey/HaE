package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.ui.Selection;
import hae.component.board.Datatable;
import hae.instances.http.utils.MessageProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;

public class ResponseEditor implements HttpResponseEditorProvider {
    private final MontoyaApi api;

    public ResponseEditor(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext editorCreationContext) {
        return new Editor(api, editorCreationContext);
    }

    private static class Editor implements ExtensionProvidedHttpResponseEditor {
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
        public HttpResponse getResponse() {
            return requestResponse.response();
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.requestResponse = requestResponse;
        }

        @Override
        public synchronized boolean isEnabledFor(HttpRequestResponse requestResponse) {
            HttpResponse request = requestResponse.response();
            if (request != null && !request.bodyToString().equals("Loading...")) {
                List<Map<String, String>> result = messageProcessor.processResponse("", request, false);
                jTabbedPane = RequestEditor.generateTabbedPaneFromResultMap(api, result);
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
}
