package hae;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import hae.cache.CachePool;
import hae.component.Main;
import hae.component.board.message.MessageTableModel;
import hae.instances.editor.RequestEditor;
import hae.instances.editor.ResponseEditor;
import hae.instances.editor.WebSocketEditor;
import hae.instances.http.HttpMessageHandler;
import hae.instances.websocket.WebSocketMessageHandler;
import hae.utils.ConfigLoader;

public class HaE implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        // 设置扩展名称
        String version = "3.3.2";
        api.extension().setName(String.format("HaE (%s) - Highlighter and Extractor", version));

        // 加载扩展后输出的项目信息
        Logging logging = api.logging();
        logging.logToOutput("[ HACK THE WORLD - TO DO IT ]");
        logging.logToOutput("[#] Author: EvilChen && 0chencc && vaycore");
        logging.logToOutput("[#] Github: https://github.com/gh0stkey/HaE");

        // 配置文件加载
        ConfigLoader configLoader = new ConfigLoader(api);

        MessageTableModel messageTableModel = new MessageTableModel(api);

        // 注册Tab页（用于查询数据）
        api.userInterface().registerSuiteTab("HaE", new Main(api, configLoader, messageTableModel));

        // 注册HTTP处理器
        api.http().registerHttpHandler(new HttpMessageHandler(api, configLoader, messageTableModel));

        // 注册WebSocket处理器
        api.proxy().registerWebSocketCreationHandler(proxyWebSocketCreation -> proxyWebSocketCreation.proxyWebSocket().registerProxyMessageHandler(new WebSocketMessageHandler(api)));

        // 注册消息编辑框（用于展示数据）
        api.userInterface().registerHttpRequestEditorProvider(new RequestEditor(api, configLoader));
        api.userInterface().registerHttpResponseEditorProvider(new ResponseEditor(api, configLoader));
        api.userInterface().registerWebSocketMessageEditorProvider(new WebSocketEditor(api, configLoader));

        api.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                // 卸载清空数据
                Config.globalDataMap.clear();
                CachePool.clear();
            }
        });
    }
}
