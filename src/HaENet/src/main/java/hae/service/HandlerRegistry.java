package hae.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import hae.component.board.message.MessageTableModel;
import hae.instances.http.HttpMessageActiveHandler;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;

public class HandlerRegistry {

    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final MessageTableModel messageTableModel;
    private final DataRepository dataRepository;
    private final RuleRepository ruleRepository;
    private Registration activeHandler;

    public HandlerRegistry(
        MontoyaApi api,
        ConfigLoader configLoader,
        MessageTableModel messageTableModel,
        DataRepository dataRepository,
        RuleRepository ruleRepository
    ) {
        this.api = api;
        this.configLoader = configLoader;
        this.messageTableModel = messageTableModel;
        this.dataRepository = dataRepository;
        this.ruleRepository = ruleRepository;
    }

    public void registerAll() {
        this.activeHandler = api
            .http()
            .registerHttpHandler(
                new HttpMessageActiveHandler(
                    api,
                    configLoader,
                    messageTableModel,
                    dataRepository,
                    ruleRepository
                )
            );
    }

    public void unregisterAll() {
        if (activeHandler != null && activeHandler.isRegistered()) {
            activeHandler.deregister();
        }
    }
}
