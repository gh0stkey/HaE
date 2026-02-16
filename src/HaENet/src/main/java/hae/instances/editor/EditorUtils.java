package hae.instances.editor;

import burp.api.montoya.MontoyaApi;
import hae.AppConstants;
import hae.component.board.table.Datatable;
import hae.utils.ConfigLoader;

import javax.swing.*;
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

    public static void generateTabbedPaneFromResultMap(MontoyaApi api, ConfigLoader configLoader, JTabbedPane tabbedPane, List<Map<String, String>> result) {
        tabbedPane.removeAll();
        if (result != null && !result.isEmpty()) {
            Map<String, String> dataMap = result.get(0);
            if (dataMap != null && !dataMap.isEmpty()) {
                dataMap.keySet().forEach(i -> {
                    String[] extractData = dataMap.get(i).split(AppConstants.boundary);
                    Datatable dataPanel = new Datatable(api, configLoader, i, Arrays.asList(extractData));
                    tabbedPane.addTab(i, dataPanel);
                });
            }
        }
    }
}
