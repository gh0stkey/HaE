package hae.instances.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import hae.component.board.ScopedDataboardDialog;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;

import javax.swing.*;
import java.awt.*;
import java.util.Collections;
import java.util.List;

public class DataboardContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final DataRepository dataRepository;
    private final RuleRepository ruleRepository;
    private final ValidatorService validatorService;

    public DataboardContextMenuProvider(MontoyaApi api, ConfigLoader configLoader,
                                        DataRepository dataRepository, RuleRepository ruleRepository,
                                        ValidatorService validatorService) {
        this.api = api;
        this.configLoader = configLoader;
        this.dataRepository = dataRepository;
        this.ruleRepository = ruleRepository;
        this.validatorService = validatorService;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
        if (selectedMessages == null || selectedMessages.isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem menuItem = new JMenuItem("View in Databoard");
        menuItem.addActionListener(e ->
                ScopedDataboardDialog.show(api, configLoader, dataRepository, ruleRepository,
                        validatorService, selectedMessages));

        return List.of(menuItem);
    }
}
