package hae.instances.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import hae.component.board.ScopedDataboardDialog;
import hae.instances.http.utils.MessageProcessor;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.awt.*;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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

        JMenuItem viewMenuItem = new JMenuItem("View in Databoard");
        viewMenuItem.addActionListener(e ->
                ScopedDataboardDialog.show(api, configLoader, dataRepository, ruleRepository,
                        validatorService, selectedMessages, false));

        JMenuItem rescanMenuItem = new JMenuItem("Rescan");
        rescanMenuItem.addActionListener(e -> rescan(selectedMessages));

        return List.of(rescanMenuItem, viewMenuItem);
    }

    private void rescan(List<HttpRequestResponse> selectedMessages) {
        MessageProcessor messageProcessor = new MessageProcessor(
                api,
                configLoader,
                dataRepository,
                ruleRepository
        );

        new SwingWorker<Integer, Void>() {
            private final Set<String> clearedHosts = new HashSet<>();

            @Override
            protected Integer doInBackground() {
                int count = 0;
                for (HttpRequestResponse message : selectedMessages) {
                    HttpRequest request = message.request();
                    if (request == null) {
                        continue;
                    }

                    try {
                        String url = request.url();
                        String host = StringProcessor.getHostByUrl(url);
                        if (host.isEmpty()) {
                            continue;
                        }

                        if (clearedHosts.add(host)) {
                            dataRepository.clearHostData(host, true);
                        }

                        messageProcessor.processRequest(
                                host,
                                url,
                                request,
                                true,
                                true,
                                true
                        );

                        HttpResponse response = message.response();
                        if (response != null) {
                            messageProcessor.processResponse(
                                    host,
                                    url,
                                    response,
                                    true,
                                    true,
                                    true
                            );
                        }
                        count++;
                    } catch (Exception ex) {
                        api.logging().logToError("Rescan: skipping malformed message: " + ex.getMessage());
                    }
                }
                return count;
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    JOptionPane.showMessageDialog(
                            api.userInterface().swingUtils().suiteFrame(),
                            String.format("Rescan completed for %s message(s).", count),
                            "HaE",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                } catch (Exception ex) {
                    api.logging().logToError("Rescan: " + ex.getMessage());
                }
            }
        }.execute();
    }
}
