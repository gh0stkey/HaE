package hae.service;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import hae.component.board.message.MessageTableModel;
import hae.instances.http.HttpMessageActiveHandler;
import hae.instances.http.HttpMessagePassiveHandler;
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
    private Registration passiveHandler;

    public HandlerRegistry(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel,
                           DataRepository dataRepository, RuleRepository ruleRepository) {
        this.api = api;
        this.configLoader = configLoader;
        this.messageTableModel = messageTableModel;
        this.dataRepository = dataRepository;
        this.ruleRepository = ruleRepository;
    }

    public void registerAll(boolean proVersion) {
        this.activeHandler = api.http().registerHttpHandler(
                new HttpMessageActiveHandler(api, configLoader, messageTableModel, dataRepository, ruleRepository));
        this.passiveHandler = api.scanner().registerScanCheck(
                new HttpMessagePassiveHandler(api, configLoader, messageTableModel, dataRepository, ruleRepository));
    }

    public void switchToActiveMode() {
        if (hae.Config.proVersionStatus && passiveHandler.isRegistered()) {
            passiveHandler.deregister();
        }

        if (!activeHandler.isRegistered()) {
            activeHandler = api.http().registerHttpHandler(
                    new HttpMessageActiveHandler(api, configLoader, messageTableModel, dataRepository, ruleRepository));
        }
    }

    public void switchToPassiveMode() {
        if (hae.Config.proVersionStatus && !passiveHandler.isRegistered()) {
            passiveHandler = api.scanner().registerScanCheck(
                    new HttpMessagePassiveHandler(api, configLoader, messageTableModel, dataRepository, ruleRepository));
        }

        if (activeHandler.isRegistered()) {
            activeHandler.deregister();
        }
    }

    public void unregisterAll() {
        if (activeHandler != null && activeHandler.isRegistered()) {
            activeHandler.deregister();
        }
        if (passiveHandler != null && passiveHandler.isRegistered()) {
            passiveHandler.deregister();
        }
    }
}
