package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import hae.AppConstants;
import hae.component.board.table.Datatable;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.string.StringProcessor;

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public final class EditorUtils {
    private EditorUtils() {
    }

    public static boolean isListHasData(List<Map<String, String>> dataList) {
        if (dataList != null && !dataList.isEmpty()) {
            Map<String, String> dataMap = dataList.get(0);
            return dataMap != null && !dataMap.isEmpty();
        }
        return false;
    }

    public static void generateTabbedPaneFromResultMap(MontoyaApi api, ConfigLoader configLoader, JTabbedPane tabbedPane, List<Map<String, String>> result, ValidatorService validatorService) {
        // 移除旧的右键监听器，防止累积
        for (java.awt.event.MouseListener ml : tabbedPane.getMouseListeners()) {
            if (ml instanceof TabRevalidateListener) {
                tabbedPane.removeMouseListener(ml);
            }
        }

        tabbedPane.removeAll();
        if (result != null && !result.isEmpty()) {
            Map<String, String> dataMap = result.get(0);
            if (dataMap != null && !dataMap.isEmpty()) {
                dataMap.keySet().forEach(i -> {
                    String ruleName = StringProcessor.extractItemName(i);
                    String[] extractData = dataMap.get(i).split(AppConstants.boundary);
                    Datatable dataPanel = new Datatable(api, configLoader, ruleName, Arrays.asList(extractData), validatorService);
                    tabbedPane.addTab(i, dataPanel);
                });
            }
        }

        if (validatorService != null && tabbedPane.getTabCount() > 0) {
            tabbedPane.addMouseListener(new TabRevalidateListener(tabbedPane, validatorService));
        }
    }

    private static class TabRevalidateListener extends MouseAdapter {
        private final JTabbedPane tabbedPane;
        private final ValidatorService validatorService;

        TabRevalidateListener(JTabbedPane tabbedPane, ValidatorService validatorService) {
            this.tabbedPane = tabbedPane;
            this.validatorService = validatorService;
        }

        @Override
        public void mousePressed(MouseEvent e) { showPopup(e); }
        @Override
        public void mouseReleased(MouseEvent e) { showPopup(e); }

        private void showPopup(MouseEvent e) {
            if (e.isPopupTrigger()) {
                int tabIndex = tabbedPane.indexAtLocation(e.getX(), e.getY());
                if (tabIndex != -1 && tabbedPane.getComponentAt(tabIndex) instanceof Datatable dt) {
                    JPopupMenu popup = new JPopupMenu();
                    JMenuItem revalidateItem = new JMenuItem("Revalidate");
                    revalidateItem.addActionListener(ev -> {
                        List<String> matches = new ArrayList<>();
                        JTable table = dt.getDataTable();
                        for (int r = 0; r < table.getModel().getRowCount(); r++) {
                            matches.add(table.getModel().getValueAt(r, 1).toString());
                        }
                        if (!matches.isEmpty()) {
                            validatorService.revalidateAll(Map.of(dt.getTabName(), matches), null, () ->
                                    SwingUtilities.invokeLater(dt::refreshSeverities));
                        }
                    });
                    popup.add(revalidateItem);
                    popup.show(tabbedPane, e.getX(), e.getY());
                }
            }
        }
    }
}
