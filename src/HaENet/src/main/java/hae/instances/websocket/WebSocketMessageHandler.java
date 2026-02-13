package hae.instances.websocket;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.websocket.*;
import hae.instances.http.utils.MessageProcessor;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;

import java.util.List;
import java.util.Map;

public class WebSocketMessageHandler implements ProxyMessageHandler {
    private final MontoyaApi api;
    private final MessageProcessor messageProcessor;

    public WebSocketMessageHandler(MontoyaApi api, ConfigLoader configLoader,
                                   DataRepository dataRepository, RuleRepository ruleRepository) {
        this.api = api;
        this.messageProcessor = new MessageProcessor(api, configLoader, dataRepository, ruleRepository);
    }

    @Override
    public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage interceptedTextMessage) {
        String message = interceptedTextMessage.payload();
        List<Map<String, String>> result = messageProcessor.processMessage("", message, true);

        if (result != null && !result.isEmpty()) {
            interceptedTextMessage.annotations().setHighlightColor(HighlightColor.highlightColor(result.get(0).get("color")));
            interceptedTextMessage.annotations().setNotes(result.get(1).get("comment"));
        }

        return TextMessageReceivedAction.continueWith(interceptedTextMessage);
    }

    @Override
    public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage interceptedTextMessage) {
        return TextMessageToBeSentAction.continueWith(interceptedTextMessage);
    }

    @Override
    public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage interceptedBinaryMessage) {
        return BinaryMessageReceivedAction.continueWith(interceptedBinaryMessage);
    }

    @Override
    public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage interceptedBinaryMessage) {
        return BinaryMessageToBeSentAction.continueWith(interceptedBinaryMessage);
    }
}
