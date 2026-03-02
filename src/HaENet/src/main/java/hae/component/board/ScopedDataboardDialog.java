package hae.component.board;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import hae.AppConstants;
import hae.component.board.message.MessageTableModel;
import hae.instances.http.utils.MessageProcessor;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.*;
import java.util.List;
import javax.swing.*;

public class ScopedDataboardDialog extends JDialog {

    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final ValidatorService validatorService;
    private final MessageTableModel messageTableModel;
    private final JTabbedPane dataTabbedPane;
    private final JSplitPane splitPane;
    private MessageTableModel.MessageTable messageTable;

    private ScopedDataboardDialog(
        MontoyaApi api,
        ConfigLoader configLoader,
        RuleRepository ruleRepository,
        ValidatorService validatorService
    ) {
        super((Frame) null, "HaE Databoard", false);
        this.api = api;
        this.configLoader = configLoader;
        this.validatorService = validatorService;
        this.messageTableModel = new MessageTableModel(
            api,
            configLoader,
            ruleRepository
        );

        this.dataTabbedPane = new JTabbedPane(JTabbedPane.TOP);
        this.dataTabbedPane.setPreferredSize(new Dimension(500, 0));
        this.dataTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        this.splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        initLayout();
    }

    private void initLayout() {
        Rectangle screenBounds =
            GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getDefaultScreenDevice()
                .getDefaultConfiguration()
                .getBounds();
        setSize(
            (int) (screenBounds.width * 0.7),
            (int) (screenBounds.height * 0.7)
        );
        setLocationRelativeTo(null);

        setLayout(new BorderLayout());
        add(splitPane, BorderLayout.CENTER);

        splitPane.addComponentListener(
            new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    resizePanel();
                }
            }
        );

        addWindowListener(
            new java.awt.event.WindowAdapter() {
                @Override
                public void windowClosed(java.awt.event.WindowEvent e) {
                    messageTableModel.dispose();
                }
            }
        );
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private void resizePanel() {
        if (messageTable == null) {
            return;
        }
        Databoard.resizeMessageTable(splitPane, messageTable, getWidth());
    }

    private void populateData(Map<String, List<String>> ruleData) {
        dataTabbedPane.addChangeListener(e -> {
            int selectedIndex = dataTabbedPane.getSelectedIndex();
            if (selectedIndex == -1) {
                return;
            }
            String selectedTitle = dataTabbedPane.getTitleAt(selectedIndex);
            new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() {
                    messageTableModel.applyCommentFilter(
                        StringProcessor.extractItemName(selectedTitle)
                    );
                    return null;
                }
            }
                .execute();
        });

        Databoard.populateTabs(
            dataTabbedPane,
            ruleData,
            api,
            configLoader,
            validatorService,
            messageTableModel
        );

        splitPane.setLeftComponent(dataTabbedPane);
        splitPane.setRightComponent(messageTableModel.getSplitPane());
        messageTable = messageTableModel.getMessageTable();
        dataTabbedPane.setSelectedIndex(0);
    }

    public static void show(
        MontoyaApi api,
        ConfigLoader configLoader,
        DataRepository dataRepository,
        RuleRepository ruleRepository,
        ValidatorService validatorService,
        List<HttpRequestResponse> messages
    ) {
        MessageProcessor messageProcessor = new MessageProcessor(
            api,
            configLoader,
            dataRepository,
            ruleRepository
        );

        new SwingWorker<Void, Void>() {
            private final Map<String, List<String>> ruleDataMap =
                new LinkedHashMap<>();
            private final List<Object[]> messageEntries = new ArrayList<>();

            @Override
            protected Void doInBackground() {
                for (HttpRequestResponse message : messages) {
                    HttpRequest request = message.request();
                    if (request == null) {
                        continue;
                    }

                    try {
                        String url = request.url();
                        String host = StringProcessor.getHostByUrl(url);
                        HttpResponse response = message.response();

                        List<Map<String, String>> reqHighlight =
                            messageProcessor.processRequest(
                                host,
                                url,
                                request,
                                true
                            );
                        List<Map<String, String>> respHighlight = null;
                        if (response != null) {
                            respHighlight = messageProcessor.processResponse(
                                host,
                                url,
                                response,
                                true
                            );
                        }

                        List<String> colorList = new ArrayList<>();
                        List<String> commentList = new ArrayList<>();
                        collectHighlight(reqHighlight, colorList, commentList);
                        collectHighlight(respHighlight, colorList, commentList);

                        if (!colorList.isEmpty()) {
                            String color = messageProcessor.retrieveFinalColor(
                                messageProcessor.retrieveColorIndices(colorList)
                            );
                            String comment = StringProcessor.mergeComment(
                                String.join(", ", commentList)
                            );
                            if (!comment.isEmpty()) {
                                String status =
                                    response != null
                                        ? String.valueOf(response.statusCode())
                                        : "";
                                String length =
                                    response != null
                                        ? String.valueOf(
                                              response.toByteArray().length()
                                          )
                                        : "0";
                                messageEntries.add(
                                    new Object[] {
                                        message,
                                        url,
                                        request.method(),
                                        status,
                                        length,
                                        comment,
                                        color,
                                    }
                                );
                            }
                        }

                        mergeExtractResult(
                            ruleDataMap,
                            messageProcessor.processRequest(
                                host,
                                url,
                                request,
                                false
                            )
                        );
                        if (response != null) {
                            mergeExtractResult(
                                ruleDataMap,
                                messageProcessor.processResponse(
                                    host,
                                    url,
                                    response,
                                    false
                                )
                            );
                        }
                    } catch (Exception e) {
                        api
                            .logging()
                            .logToError(
                                "ScopedDataboardDialog: skipping malformed message: " +
                                    e.getMessage()
                            );
                    }
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    if (ruleDataMap.isEmpty()) {
                        JOptionPane.showMessageDialog(
                            null,
                            "No data could be extracted from the selected message(s).",
                            "HaE Databoard",
                            JOptionPane.INFORMATION_MESSAGE
                        );
                        return;
                    }

                    ScopedDataboardDialog dialog = new ScopedDataboardDialog(
                        api,
                        configLoader,
                        ruleRepository,
                        validatorService
                    );
                    for (Object[] entry : messageEntries) {
                        dialog.messageTableModel.add(
                            (HttpRequestResponse) entry[0],
                            (String) entry[1],
                            (String) entry[2],
                            (String) entry[3],
                            (String) entry[4],
                            (String) entry[5],
                            (String) entry[6],
                            false
                        );
                    }
                    dialog.populateData(ruleDataMap);
                    dialog.setVisible(true);
                } catch (Exception e) {
                    api
                        .logging()
                        .logToError("ScopedDataboardDialog: " + e.getMessage());
                }
            }
        }
            .execute();
    }

    private static void collectHighlight(
        List<Map<String, String>> result,
        List<String> colorList,
        List<String> commentList
    ) {
        if (result != null && !result.isEmpty()) {
            colorList.add(result.get(0).get("color"));
            commentList.add(result.get(1).get("comment"));
        }
    }

    private static void mergeExtractResult(
        Map<String, List<String>> target,
        List<Map<String, String>> extractResult
    ) {
        if (extractResult == null || extractResult.isEmpty()) {
            return;
        }
        for (Map.Entry<String, String> entry : extractResult
            .get(0)
            .entrySet()) {
            String ruleName = StringProcessor.extractItemName(entry.getKey());
            List<String> items = Arrays.asList(
                entry.getValue().split(AppConstants.boundary)
            );
            target.merge(
                ruleName,
                new ArrayList<>(items),
                (existing, incoming) -> {
                    Set<String> merged = new LinkedHashSet<>(existing);
                    merged.addAll(incoming);
                    return new ArrayList<>(merged);
                }
            );
        }
    }
}
