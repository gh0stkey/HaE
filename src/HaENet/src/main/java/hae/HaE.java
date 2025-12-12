package hae;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.logging.Logging;
import hae.cache.DataCache;
import hae.component.Main;
import hae.component.board.message.MessageTableModel;
import hae.instances.editor.RequestEditor;
import hae.instances.editor.ResponseEditor;
import hae.instances.editor.WebSocketEditor;
import hae.instances.websocket.WebSocketMessageHandler;
import hae.utils.ConfigLoader;
import hae.utils.DataManager;

public class HaE implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        // 设置扩展名称
        api.extension().setName("HaE - Highlighter and Extractor");
        String version = "4.3.2";

        // 加载扩展后输出的项目信息
        Logging logging = api.logging();
        logging.logToOutput("[ HACK THE WORLD - TO DO IT ]");
        logging.logToOutput("[#] Author: EvilChen && 0chencc && vaycore");
        logging.logToOutput("[#] Github: https://github.com/gh0stkey/HaE");
        logging.logToOutput("[#] Version: " + version);

        // 配置文件加载
        ConfigLoader configLoader = new ConfigLoader(api);

        MessageTableModel messageTableModel = new MessageTableModel(api, configLoader);

        // 设置BurpSuite专业版状态
        Config.proVersionStatus = getBurpSuiteProStatus(api);

        // 注册Tab页（用于查询数据）
        api.userInterface().registerSuiteTab("HaE", new Main(api, configLoader, messageTableModel));

        // 注册WebSocket处理器
        api.proxy().registerWebSocketCreationHandler(proxyWebSocketCreation -> proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(new WebSocketMessageHandler(api, configLoader)));

        // 注册消息编辑框（用于展示数据）
        api.userInterface().registerHttpRequestEditorProvider(new RequestEditor(api, configLoader));
        api.userInterface().registerHttpResponseEditorProvider(new ResponseEditor(api, configLoader));
        api.userInterface().registerWebSocketMessageEditorProvider(new WebSocketEditor(api, configLoader));

        // 从BurpSuite里加载数据
        DataManager dataManager = new DataManager(api);
        dataManager.loadData(messageTableModel);

        api.extension().registerUnloadingHandler(() -> {
            // 卸载清空数据
            Config.globalDataMap.clear();
            DataCache.clear();
        });
    }

    private Boolean getBurpSuiteProStatus(MontoyaApi api) {
        boolean burpSuiteProStatus = false;

        try {
            burpSuiteProStatus = api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;
        } catch (Exception ignored) {
        }

        return burpSuiteProStatus;
    }
}
