package burp;

/*
 * @(#)IBurpExtenderCallbacks.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.awt.Component;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;

/**
 * This interface is used by Burp Suite to pass to extensions a set of callback
 * methods that can be used by extensions to perform various actions within
 * Burp.
 *
 * When an extension is loaded, Burp invokes its
 * <code>registerExtenderCallbacks()</code> method and passes an instance of the
 * <code>IBurpExtenderCallbacks</code> interface. The extension may then invoke
 * the methods of this interface as required in order to extend Burp's
 * functionality.
 */
public interface IBurpExtenderCallbacks
{

    /**
     * Flag used to identify Burp Suite as a whole.
     */
    int TOOL_SUITE = 0x00000001;
    /**
     * Flag used to identify the Burp Target tool.
     */
    int TOOL_TARGET = 0x00000002;
    /**
     * Flag used to identify the Burp Proxy tool.
     */
    int TOOL_PROXY = 0x00000004;
    /**
     * Flag used to identify the Burp Spider tool.
     */
    int TOOL_SPIDER = 0x00000008;
    /**
     * Flag used to identify the Burp Scanner tool.
     */
    int TOOL_SCANNER = 0x00000010;
    /**
     * Flag used to identify the Burp Intruder tool.
     */
    int TOOL_INTRUDER = 0x00000020;
    /**
     * Flag used to identify the Burp Repeater tool.
     */
    int TOOL_REPEATER = 0x00000040;
    /**
     * Flag used to identify the Burp Sequencer tool.
     */
    int TOOL_SEQUENCER = 0x00000080;
    /**
     * Flag used to identify the Burp Decoder tool.
     */
    int TOOL_DECODER = 0x00000100;
    /**
     * Flag used to identify the Burp Comparer tool.
     */
    int TOOL_COMPARER = 0x00000200;
    /**
     * Flag used to identify the Burp Extender tool.
     */
    int TOOL_EXTENDER = 0x00000400;

    /**
     * This method is used to set the display name for the current extension,
     * which will be displayed within the user interface for the Extender tool.
     *
     * @param name The extension name.
     */
    void setExtensionName(String name);

    /**
     * This method is used to obtain an <code>IExtensionHelpers</code> object,
     * which can be used by the extension to perform numerous useful tasks.
     *
     * @return An object containing numerous helper methods, for tasks such as
     * building and analyzing HTTP requests.
     */
    IExtensionHelpers getHelpers();

    /**
     * This method is used to obtain the current extension's standard output
     * stream. Extensions should write all output to this stream, allowing the
     * Burp user to configure how that output is handled from within the UI.
     *
     * @return The extension's standard output stream.
     */
    OutputStream getStdout();

    /**
     * This method is used to obtain the current extension's standard error
     * stream. Extensions should write all error messages to this stream,
     * allowing the Burp user to configure how that output is handled from
     * within the UI.
     *
     * @return The extension's standard error stream.
     */
    OutputStream getStderr();

    /**
     * This method prints a line of output to the current extension's standard
     * output stream.
     *
     * @param output The message to print.
     */
    void printOutput(String output);

    /**
     * This method prints a line of output to the current extension's standard
     * error stream.
     *
     * @param error The message to print.
     */
    void printError(String error);

    /**
     * This method is used to register a listener which will be notified of
     * changes to the extension's state. <b>Note:</b> Any extensions that start
     * background threads or open system resources (such as files or database
     * connections) should register a listener and terminate threads / close
     * resources when the extension is unloaded.
     *
     * @param listener An object created by the extension that implements the
     * <code>IExtensionStateListener</code> interface.
     */
    void registerExtensionStateListener(IExtensionStateListener listener);

    /**
     * This method is used to retrieve the extension state listeners that are
     * registered by the extension.
     *
     * @return A list of extension state listeners that are currently registered
     * by this extension.
     */
    List<IExtensionStateListener> getExtensionStateListeners();

    /**
     * This method is used to remove an extension state listener that has been
     * registered by the extension.
     *
     * @param listener The extension state listener to be removed.
     */
    void removeExtensionStateListener(IExtensionStateListener listener);

    /**
     * This method is used to register a listener which will be notified of
     * requests and responses made by any Burp tool. Extensions can perform
     * custom analysis or modification of these messages by registering an HTTP
     * listener.
     *
     * @param listener An object created by the extension that implements the
     * <code>IHttpListener</code> interface.
     */
    void registerHttpListener(IHttpListener listener);

    /**
     * This method is used to retrieve the HTTP listeners that are registered by
     * the extension.
     *
     * @return A list of HTTP listeners that are currently registered by this
     * extension.
     */
    List<IHttpListener> getHttpListeners();

    /**
     * This method is used to remove an HTTP listener that has been registered
     * by the extension.
     *
     * @param listener The HTTP listener to be removed.
     */
    void removeHttpListener(IHttpListener listener);

    /**
     * This method is used to register a listener which will be notified of
     * requests and responses being processed by the Proxy tool. Extensions can
     * perform custom analysis or modification of these messages, and control
     * in-UI message interception, by registering a proxy listener.
     *
     * @param listener An object created by the extension that implements the
     * <code>IProxyListener</code> interface.
     */
    void registerProxyListener(IProxyListener listener);

    /**
     * This method is used to retrieve the Proxy listeners that are registered
     * by the extension.
     *
     * @return A list of Proxy listeners that are currently registered by this
     * extension.
     */
    List<IProxyListener> getProxyListeners();

    /**
     * This method is used to remove a Proxy listener that has been registered
     * by the extension.
     *
     * @param listener The Proxy listener to be removed.
     */
    void removeProxyListener(IProxyListener listener);

    /**
     * This method is used to register a listener which will be notified of new
     * issues that are reported by the Scanner tool. Extensions can perform
     * custom analysis or logging of Scanner issues by registering a Scanner
     * listener.
     *
     * @param listener An object created by the extension that implements the
     * <code>IScannerListener</code> interface.
     */
    void registerScannerListener(IScannerListener listener);

    /**
     * This method is used to retrieve the Scanner listeners that are registered
     * by the extension.
     *
     * @return A list of Scanner listeners that are currently registered by this
     * extension.
     */
    List<IScannerListener> getScannerListeners();

    /**
     * This method is used to remove a Scanner listener that has been registered
     * by the extension.
     *
     * @param listener The Scanner listener to be removed.
     */
    void removeScannerListener(IScannerListener listener);

    /**
     * This method is used to register a listener which will be notified of
     * changes to Burp's suite-wide target scope.
     *
     * @param listener An object created by the extension that implements the
     * <code>IScopeChangeListener</code> interface.
     */
    void registerScopeChangeListener(IScopeChangeListener listener);

    /**
     * This method is used to retrieve the scope change listeners that are
     * registered by the extension.
     *
     * @return A list of scope change listeners that are currently registered by
     * this extension.
     */
    List<IScopeChangeListener> getScopeChangeListeners();

    /**
     * This method is used to remove a scope change listener that has been
     * registered by the extension.
     *
     * @param listener The scope change listener to be removed.
     */
    void removeScopeChangeListener(IScopeChangeListener listener);

    /**
     * This method is used to register a factory for custom context menu items.
     * When the user invokes a context menu anywhere within Burp, the factory
     * will be passed details of the invocation event, and asked to provide any
     * custom context menu items that should be shown.
     *
     * @param factory An object created by the extension that implements the
     * <code>IContextMenuFactory</code> interface.
     */
    void registerContextMenuFactory(IContextMenuFactory factory);

    /**
     * This method is used to retrieve the context menu factories that are
     * registered by the extension.
     *
     * @return A list of context menu factories that are currently registered by
     * this extension.
     */
    List<IContextMenuFactory> getContextMenuFactories();

    /**
     * This method is used to remove a context menu factory that has been
     * registered by the extension.
     *
     * @param factory The context menu factory to be removed.
     */
    void removeContextMenuFactory(IContextMenuFactory factory);

    /**
     * This method is used to register a factory for custom message editor tabs.
     * For each message editor that already exists, or is subsequently created,
     * within Burp, the factory will be asked to provide a new instance of an
     * <code>IMessageEditorTab</code> object, which can provide custom rendering
     * or editing of HTTP messages.
     *
     * @param factory An object created by the extension that implements the
     * <code>IMessageEditorTabFactory</code> interface.
     */
    void registerMessageEditorTabFactory(IMessageEditorTabFactory factory);

    /**
     * This method is used to retrieve the message editor tab factories that are
     * registered by the extension.
     *
     * @return A list of message editor tab factories that are currently
     * registered by this extension.
     */
    List<IMessageEditorTabFactory> getMessageEditorTabFactories();

    /**
     * This method is used to remove a message editor tab factory that has been
     * registered by the extension.
     *
     * @param factory The message editor tab factory to be removed.
     */
    void removeMessageEditorTabFactory(IMessageEditorTabFactory factory);

    /**
     * This method is used to register a provider of Scanner insertion points.
     * For each base request that is actively scanned, Burp will ask the
     * provider to provide any custom scanner insertion points that are
     * appropriate for the request.
     *
     * @param provider An object created by the extension that implements the
     * <code>IScannerInsertionPointProvider</code> interface.
     */
    void registerScannerInsertionPointProvider(
            IScannerInsertionPointProvider provider);

    /**
     * This method is used to retrieve the Scanner insertion point providers
     * that are registered by the extension.
     *
     * @return A list of Scanner insertion point providers that are currently
     * registered by this extension.
     */
    List<IScannerInsertionPointProvider> getScannerInsertionPointProviders();

    /**
     * This method is used to remove a Scanner insertion point provider that has
     * been registered by the extension.
     *
     * @param provider The Scanner insertion point provider to be removed.
     */
    void removeScannerInsertionPointProvider(
            IScannerInsertionPointProvider provider);

    /**
     * This method is used to register a custom Scanner check. When performing
     * scanning, Burp will ask the check to perform active or passive scanning
     * on the base request, and report any Scanner issues that are identified.
     *
     * @param check An object created by the extension that implements the
     * <code>IScannerCheck</code> interface.
     */
    void registerScannerCheck(IScannerCheck check);

    /**
     * This method is used to retrieve the Scanner checks that are registered by
     * the extension.
     *
     * @return A list of Scanner checks that are currently registered by this
     * extension.
     */
    List<IScannerCheck> getScannerChecks();

    /**
     * This method is used to remove a Scanner check that has been registered by
     * the extension.
     *
     * @param check The Scanner check to be removed.
     */
    void removeScannerCheck(IScannerCheck check);

    /**
     * This method is used to register a factory for Intruder payloads. Each
     * registered factory will be available within the Intruder UI for the user
     * to select as the payload source for an attack. When this is selected, the
     * factory will be asked to provide a new instance of an
     * <code>IIntruderPayloadGenerator</code> object, which will be used to
     * generate payloads for the attack.
     *
     * @param factory An object created by the extension that implements the
     * <code>IIntruderPayloadGeneratorFactory</code> interface.
     */
    void registerIntruderPayloadGeneratorFactory(
            IIntruderPayloadGeneratorFactory factory);

    /**
     * This method is used to retrieve the Intruder payload generator factories
     * that are registered by the extension.
     *
     * @return A list of Intruder payload generator factories that are currently
     * registered by this extension.
     */
    List<IIntruderPayloadGeneratorFactory>
            getIntruderPayloadGeneratorFactories();

    /**
     * This method is used to remove an Intruder payload generator factory that
     * has been registered by the extension.
     *
     * @param factory The Intruder payload generator factory to be removed.
     */
    void removeIntruderPayloadGeneratorFactory(
            IIntruderPayloadGeneratorFactory factory);

    /**
     * This method is used to register a custom Intruder payload processor. Each
     * registered processor will be available within the Intruder UI for the
     * user to select as the action for a payload processing rule.
     *
     * @param processor An object created by the extension that implements the
     * <code>IIntruderPayloadProcessor</code> interface.
     */
    void registerIntruderPayloadProcessor(IIntruderPayloadProcessor processor);

    /**
     * This method is used to retrieve the Intruder payload processors that are
     * registered by the extension.
     *
     * @return A list of Intruder payload processors that are currently
     * registered by this extension.
     */
    List<IIntruderPayloadProcessor> getIntruderPayloadProcessors();

    /**
     * This method is used to remove an Intruder payload processor that has been
     * registered by the extension.
     *
     * @param processor The Intruder payload processor to be removed.
     */
    void removeIntruderPayloadProcessor(IIntruderPayloadProcessor processor);

    /**
     * This method is used to register a custom session handling action. Each
     * registered action will be available within the session handling rule UI
     * for the user to select as a rule action. Users can choose to invoke an
     * action directly in its own right, or following execution of a macro.
     *
     * @param action An object created by the extension that implements the
     * <code>ISessionHandlingAction</code> interface.
     */
    void registerSessionHandlingAction(ISessionHandlingAction action);

    /**
     * This method is used to retrieve the session handling actions that are
     * registered by the extension.
     *
     * @return A list of session handling actions that are currently registered
     * by this extension.
     */
    List<ISessionHandlingAction> getSessionHandlingActions();

    /**
     * This method is used to remove a session handling action that has been
     * registered by the extension.
     *
     * @param action The extension session handling action to be removed.
     */
    void removeSessionHandlingAction(ISessionHandlingAction action);

    /**
     * This method is used to unload the extension from Burp Suite.
     */
    void unloadExtension();

    /**
     * This method is used to add a custom tab to the main Burp Suite window.
     *
     * @param tab An object created by the extension that implements the
     * <code>ITab</code> interface.
     */
    void addSuiteTab(ITab tab);

    /**
     * This method is used to remove a previously-added tab from the main Burp
     * Suite window.
     *
     * @param tab An object created by the extension that implements the
     * <code>ITab</code> interface.
     */
    void removeSuiteTab(ITab tab);

    /**
     * This method is used to customize UI components in line with Burp's UI
     * style, including font size, colors, table line spacing, etc. The action
     * is performed recursively on any child components of the passed-in
     * component.
     *
     * @param component The UI component to be customized.
     */
    void customizeUiComponent(Component component);

    /**
     * This method is used to create a new instance of Burp's HTTP message
     * editor, for the extension to use in its own UI.
     *
     * @param controller An object created by the extension that implements the
     * <code>IMessageEditorController</code> interface. This parameter is
     * optional and may be <code>null</code>. If it is provided, then the
     * message editor will query the controller when required to obtain details
     * about the currently displayed message, including the
     * <code>IHttpService</code> for the message, and the associated request or
     * response message. If a controller is not provided, then the message
     * editor will not support context menu actions, such as sending requests to
     * other Burp tools.
     * @param editable Indicates whether the editor created should be editable,
     * or used only for message viewing.
     * @return An object that implements the <code>IMessageEditor</code>
     * interface, and which the extension can use in its own UI.
     */
    IMessageEditor createMessageEditor(IMessageEditorController controller,
            boolean editable);

    /**
     * This method returns the command line arguments that were passed to Burp
     * on startup.
     *
     * @return The command line arguments that were passed to Burp on startup.
     */
    String[] getCommandLineArguments();

    /**
     * This method is used to save configuration settings for the extension in a
     * persistent way that survives reloads of the extension and of Burp Suite.
     * Saved settings can be retrieved using the method
     * <code>loadExtensionSetting()</code>.
     *
     * @param name The name of the setting.
     * @param value The value of the setting. If this value is <code>null</code>
     * then any existing setting with the specified name will be removed.
     */
    void saveExtensionSetting(String name, String value);

    /**
     * This method is used to load configuration settings for the extension that
     * were saved using the method <code>saveExtensionSetting()</code>.
     *
     * @param name The name of the setting.
     * @return The value of the setting, or <code>null</code> if no value is
     * set.
     */
    String loadExtensionSetting(String name);

    /**
     * This method is used to create a new instance of Burp's plain text editor,
     * for the extension to use in its own UI.
     *
     * @return An object that implements the <code>ITextEditor</code> interface,
     * and which the extension can use in its own UI.
     */
    ITextEditor createTextEditor();

    /**
     * This method can be used to send an HTTP request to the Burp Repeater
     * tool. The request will be displayed in the user interface, but will not
     * be issued until the user initiates this action.
     *
     * @param host The hostname of the remote HTTP server.
     * @param port The port of the remote HTTP server.
     * @param useHttps Flags whether the protocol is HTTPS or HTTP.
     * @param request The full HTTP request.
     * @param tabCaption An optional caption which will appear on the Repeater
     * tab containing the request. If this value is <code>null</code> then a
     * default tab index will be displayed.
     */
    void sendToRepeater(
            String host,
            int port,
            boolean useHttps,
            byte[] request,
            String tabCaption);

    /**
     * This method can be used to send an HTTP request to the Burp Intruder
     * tool. The request will be displayed in the user interface, and markers
     * for attack payloads will be placed into default locations within the
     * request.
     *
     * @param host The hostname of the remote HTTP server.
     * @param port The port of the remote HTTP server.
     * @param useHttps Flags whether the protocol is HTTPS or HTTP.
     * @param request The full HTTP request.
     */
    void sendToIntruder(
            String host,
            int port,
            boolean useHttps,
            byte[] request);

    /**
     * This method can be used to send an HTTP request to the Burp Intruder
     * tool. The request will be displayed in the user interface, and markers
     * for attack payloads will be placed into the specified locations within
     * the request.
     *
     * @param host The hostname of the remote HTTP server.
     * @param port The port of the remote HTTP server.
     * @param useHttps Flags whether the protocol is HTTPS or HTTP.
     * @param request The full HTTP request.
     * @param payloadPositionOffsets A list of index pairs representing the
     * payload positions to be used. Each item in the list must be an int[2]
     * array containing the start and end offsets for the payload position.
     */
    void sendToIntruder(
            String host,
            int port,
            boolean useHttps,
            byte[] request,
            List<int[]> payloadPositionOffsets);

    /**
     * This method can be used to send data to the Comparer tool.
     *
     * @param data The data to be sent to Comparer.
     */
    void sendToComparer(byte[] data);

    /**
     * This method can be used to send a seed URL to the Burp Spider tool. If
     * the URL is not within the current Spider scope, the user will be asked if
     * they wish to add the URL to the scope. If the Spider is not currently
     * running, it will be started. The seed URL will be requested, and the
     * Spider will process the application's response in the normal way.
     *
     * @param url The new seed URL to begin spidering from.
     */
    void sendToSpider(
            java.net.URL url);

    /**
     * This method can be used to send an HTTP request to the Burp Scanner tool
     * to perform an active vulnerability scan. If the request is not within the
     * current active scanning scope, the user will be asked if they wish to
     * proceed with the scan.
     *
     * @param host The hostname of the remote HTTP server.
     * @param port The port of the remote HTTP server.
     * @param useHttps Flags whether the protocol is HTTPS or HTTP.
     * @param request The full HTTP request.
     * @return The resulting scan queue item.
     */
    IScanQueueItem doActiveScan(
            String host,
            int port,
            boolean useHttps,
            byte[] request);

    /**
     * This method can be used to send an HTTP request to the Burp Scanner tool
     * to perform an active vulnerability scan, based on a custom list of
     * insertion points that are to be scanned. If the request is not within the
     * current active scanning scope, the user will be asked if they wish to
     * proceed with the scan.
     *
     * @param host The hostname of the remote HTTP server.
     * @param port The port of the remote HTTP server.
     * @param useHttps Flags whether the protocol is HTTPS or HTTP.
     * @param request The full HTTP request.
     * @param insertionPointOffsets A list of index pairs representing the
     * positions of the insertion points that should be scanned. Each item in
     * the list must be an int[2] array containing the start and end offsets for
     * the insertion point.
     * @return The resulting scan queue item.
     */
    IScanQueueItem doActiveScan(
            String host,
            int port,
            boolean useHttps,
            byte[] request,
            List<int[]> insertionPointOffsets);

    /**
     * This method can be used to send an HTTP request to the Burp Scanner tool
     * to perform a passive vulnerability scan.
     *
     * @param host The hostname of the remote HTTP server.
     * @param port The port of the remote HTTP server.
     * @param useHttps Flags whether the protocol is HTTPS or HTTP.
     * @param request The full HTTP request.
     * @param response The full HTTP response.
     */
    void doPassiveScan(
            String host,
            int port,
            boolean useHttps,
            byte[] request,
            byte[] response);

    /**
     * This method can be used to issue HTTP requests and retrieve their
     * responses.
     *
     * @param httpService The HTTP service to which the request should be sent.
     * @param request The full HTTP request.
     * @return An object that implements the <code>IHttpRequestResponse</code>
     * interface, and which the extension can query to obtain the details of the
     * response.
     */
    IHttpRequestResponse makeHttpRequest(IHttpService httpService,
            byte[] request);

    /**
     * This method can be used to issue HTTP requests and retrieve their
     * responses.
     *
     * @param host The hostname of the remote HTTP server.
     * @param port The port of the remote HTTP server.
     * @param useHttps Flags whether the protocol is HTTPS or HTTP.
     * @param request The full HTTP request.
     * @return The full response retrieved from the remote server.
     */
    byte[] makeHttpRequest(
            String host,
            int port,
            boolean useHttps,
            byte[] request);

    /**
     * This method can be used to query whether a specified URL is within the
     * current Suite-wide scope.
     *
     * @param url The URL to query.
     * @return Returns <code>true</code> if the URL is within the current
     * Suite-wide scope.
     */
    boolean isInScope(java.net.URL url);

    /**
     * This method can be used to include the specified URL in the Suite-wide
     * scope.
     *
     * @param url The URL to include in the Suite-wide scope.
     */
    void includeInScope(java.net.URL url);

    /**
     * This method can be used to exclude the specified URL from the Suite-wide
     * scope.
     *
     * @param url The URL to exclude from the Suite-wide scope.
     */
    void excludeFromScope(java.net.URL url);

    /**
     * This method can be used to display a specified message in the Burp Suite
     * alerts tab.
     *
     * @param message The alert message to display.
     */
    void issueAlert(String message);

    /**
     * This method returns details of all items in the Proxy history.
     *
     * @return The contents of the Proxy history.
     */
    IHttpRequestResponse[] getProxyHistory();

    /**
     * This method returns details of items in the site map.
     *
     * @param urlPrefix This parameter can be used to specify a URL prefix, in
     * order to extract a specific subset of the site map. The method performs a
     * simple case-sensitive text match, returning all site map items whose URL
     * begins with the specified prefix. If this parameter is null, the entire
     * site map is returned.
     *
     * @return Details of items in the site map.
     */
    IHttpRequestResponse[] getSiteMap(String urlPrefix);

    /**
     * This method returns all of the current scan issues for URLs matching the
     * specified literal prefix.
     *
     * @param urlPrefix This parameter can be used to specify a URL prefix, in
     * order to extract a specific subset of scan issues. The method performs a
     * simple case-sensitive text match, returning all scan issues whose URL
     * begins with the specified prefix. If this parameter is null, all issues
     * are returned.
     * @return Details of the scan issues.
     */
    IScanIssue[] getScanIssues(String urlPrefix);

    /**
     * This method is used to generate a report for the specified Scanner
     * issues. The report format can be specified. For all other reporting
     * options, the default settings that appear in the reporting UI wizard are
     * used.
     *
     * @param format The format to be used in the report. Accepted values are
     * HTML and XML.
     * @param issues The Scanner issues to be reported.
     * @param file The file to which the report will be saved.
     */
    void generateScanReport(String format, IScanIssue[] issues,
            java.io.File file);

    /**
     * This method is used to retrieve the contents of Burp's session handling
     * cookie jar. Extensions that provide an
     * <code>ISessionHandlingAction</code> can query and update the cookie jar
     * in order to handle unusual session handling mechanisms.
     *
     * @return A list of <code>ICookie</code> objects representing the contents
     * of Burp's session handling cookie jar.
     */
    List<ICookie> getCookieJarContents();

    /**
     * This method is used to update the contents of Burp's session handling
     * cookie jar. Extensions that provide an
     * <code>ISessionHandlingAction</code> can query and update the cookie jar
     * in order to handle unusual session handling mechanisms.
     *
     * @param cookie An <code>ICookie</code> object containing details of the
     * cookie to be updated. If the cookie jar already contains a cookie that
     * matches the specified domain and name, then that cookie will be updated
     * with the new value and expiration, unless the new value is
     * <code>null</code>, in which case the cookie will be removed. If the
     * cookie jar does not already contain a cookie that matches the specified
     * domain and name, then the cookie will be added.
     */
    void updateCookieJar(ICookie cookie);

    /**
     * This method can be used to add an item to Burp's site map with the
     * specified request/response details. This will overwrite the details of
     * any existing matching item in the site map.
     *
     * @param item Details of the item to be added to the site map
     */
    void addToSiteMap(IHttpRequestResponse item);

    /**
     * This method can be used to restore Burp's state from a specified saved
     * state file. This method blocks until the restore operation is completed,
     * and must not be called from the event dispatch thread.
     *
     * @param file The file containing Burp's saved state.
     * @deprecated State files have been replaced with Burp project files.
     */
    @Deprecated
    void restoreState(java.io.File file);

    /**
     * This method can be used to save Burp's state to a specified file. This
     * method blocks until the save operation is completed, and must not be
     * called from the event dispatch thread.
     *
     * @param file The file to save Burp's state in.
     * @deprecated State files have been replaced with Burp project files.
     */
    @Deprecated
    void saveState(java.io.File file);

    /**
     * This method is no longer supported. Please use saveConfigAsJson() instead.
     *
     * @return A Map of name/value Strings reflecting Burp's current
     * configuration.
     * @deprecated Use <code>saveConfigAsJson()</code> instead.
     */
    @Deprecated
    Map<String, String> saveConfig();

    /**
     * This method is no longer supported. Please use loadConfigFromJson() instead.
     *
     * @param config A map of name/value Strings to use as Burp's new
     * configuration.
     * @deprecated Use <code>loadConfigFromJson()</code> instead.
     */
    @Deprecated
    void loadConfig(Map<String, String> config);

    /**
     * This method causes Burp to save its current project-level configuration
     * in JSON format. This is the same format that can be saved and loaded via
     * the Burp user interface. To include only certain sections of the
     * configuration, you can optionally supply the path to each section that
     * should be included, for example: "project_options.connections". If no
     * paths are provided, then the entire configuration will be saved.
     *
     * @param configPaths A list of Strings representing the path to each
     * configuration section that should be included.
     * @return A String representing the current configuration in JSON format.
     */
    String saveConfigAsJson(String... configPaths);

    /**
     * This method causes Burp to load a new project-level configuration from
     * the JSON String provided. This is the same format that can be saved and
     * loaded via the Burp user interface. Partial configurations are
     * acceptable, and any settings not specified will be left unmodified.
     *
     * Any user-level configuration options contained in the input will be
     * ignored.
     *
     * @param config A JSON String containing the new configuration.
     */
    void loadConfigFromJson(String config);

    /**
     * This method sets the master interception mode for Burp Proxy.
     *
     * @param enabled Indicates whether interception of Proxy messages should be
     * enabled.
     */
    void setProxyInterceptionEnabled(boolean enabled);

    /**
     * This method retrieves information about the version of Burp in which the
     * extension is running. It can be used by extensions to dynamically adjust
     * their behavior depending on the functionality and APIs supported by the
     * current version.
     *
     * @return An array of Strings comprised of: the product name (e.g. Burp
     * Suite Professional), the major version (e.g. 1.5), the minor version
     * (e.g. 03)
     */
    String[] getBurpVersion();

    /**
     * This method retrieves the absolute path name of the file from which the
     * current extension was loaded.
     *
     * @return The absolute path name of the file from which the current
     * extension was loaded.
     */
    String getExtensionFilename();

    /**
     * This method determines whether the current extension was loaded as a BApp
     * (a Burp App from the BApp Store).
     *
     * @return Returns true if the current extension was loaded as a BApp.
     */
    boolean isExtensionBapp();

    /**
     * This method can be used to shut down Burp programmatically, with an
     * optional prompt to the user. If the method returns, the user canceled the
     * shutdown prompt.
     *
     * @param promptUser Indicates whether to prompt the user to confirm the
     * shutdown.
     */
    void exitSuite(boolean promptUser);

    /**
     * This method is used to create a temporary file on disk containing the
     * provided data. Extensions can use temporary files for long-term storage
     * of runtime data, avoiding the need to retain that data in memory.
     *
     * @param buffer The data to be saved to a temporary file.
     * @return An object that implements the <code>ITempFile</code> interface.
     */
    ITempFile saveToTempFile(byte[] buffer);

    /**
     * This method is used to save the request and response of an
     * <code>IHttpRequestResponse</code> object to temporary files, so that they
     * are no longer held in memory. Extensions can used this method to convert
     * <code>IHttpRequestResponse</code> objects into a form suitable for
     * long-term storage.
     *
     * @param httpRequestResponse The <code>IHttpRequestResponse</code> object
     * whose request and response messages are to be saved to temporary files.
     * @return An object that implements the
     * <code>IHttpRequestResponsePersisted</code> interface.
     */
    IHttpRequestResponsePersisted saveBuffersToTempFiles(
            IHttpRequestResponse httpRequestResponse);

    /**
     * This method is used to apply markers to an HTTP request or response, at
     * offsets into the message that are relevant for some particular purpose.
     * Markers are used in various situations, such as specifying Intruder
     * payload positions, Scanner insertion points, and highlights in Scanner
     * issues.
     *
     * @param httpRequestResponse The <code>IHttpRequestResponse</code> object
     * to which the markers should be applied.
     * @param requestMarkers A list of index pairs representing the offsets of
     * markers to be applied to the request message. Each item in the list must
     * be an int[2] array containing the start and end offsets for the marker.
     * The markers in the list should be in sequence and not overlapping. This
     * parameter is optional and may be <code>null</code> if no request markers
     * are required.
     * @param responseMarkers A list of index pairs representing the offsets of
     * markers to be applied to the response message. Each item in the list must
     * be an int[2] array containing the start and end offsets for the marker.
     * The markers in the list should be in sequence and not overlapping. This
     * parameter is optional and may be <code>null</code> if no response markers
     * are required.
     * @return An object that implements the
     * <code>IHttpRequestResponseWithMarkers</code> interface.
     */
    IHttpRequestResponseWithMarkers applyMarkers(
            IHttpRequestResponse httpRequestResponse,
            List<int[]> requestMarkers,
            List<int[]> responseMarkers);

    /**
     * This method is used to obtain the descriptive name for the Burp tool
     * identified by the tool flag provided.
     *
     * @param toolFlag A flag identifying a Burp tool ( <code>TOOL_PROXY</code>,
     * <code>TOOL_SCANNER</code>, etc.). Tool flags are defined within this
     * interface.
     * @return The descriptive name for the specified tool.
     */
    String getToolName(int toolFlag);

    /**
     * This method is used to register a new Scanner issue. <b>Note:</b>
     * Wherever possible, extensions should implement custom Scanner checks
     * using <code>IScannerCheck</code> and report issues via those checks, so
     * as to integrate with Burp's user-driven workflow, and ensure proper
     * consolidation of duplicate reported issues. This method is only designed
     * for tasks outside of the normal testing workflow, such as importing
     * results from other scanning tools.
     *
     * @param issue An object created by the extension that implements the
     * <code>IScanIssue</code> interface.
     */
    void addScanIssue(IScanIssue issue);

    /**
     * This method is used to create a new Burp Collaborator client context,
     * which can be used to generate Burp Collaborator payloads and poll the
     * Collaborator server for any network interactions that result from using
     * those payloads.
     *
     * @return A new instance of  <code>IBurpCollaboratorClientContext</code>
     * that can be used to generate Collaborator payloads and retrieve
     * interactions.
     */
    IBurpCollaboratorClientContext createBurpCollaboratorClientContext();

    /**
     * This method parses the specified request and returns details of each
     * request parameter.
     *
     * @param request The request to be parsed.
     * @return An array of: <code>String[] { name, value, type }</code>
     * containing details of the parameters contained within the request.
     * @deprecated Use <code>IExtensionHelpers.analyzeRequest()</code> instead.
     */
    @Deprecated
    String[][] getParameters(byte[] request);

    /**
     * This method parses the specified request and returns details of each HTTP
     * header.
     *
     * @param message The request to be parsed.
     * @return An array of HTTP headers.
     * @deprecated Use <code>IExtensionHelpers.analyzeRequest()</code> or
     * <code>IExtensionHelpers.analyzeResponse()</code> instead.
     */
    @Deprecated
    String[] getHeaders(byte[] message);

    /**
     * This method can be used to register a new menu item which will appear on
     * the various context menus that are used throughout Burp Suite to handle
     * user-driven actions.
     *
     * @param menuItemCaption The caption to be displayed on the menu item.
     * @param menuItemHandler The handler to be invoked when the user clicks on
     * the menu item.
     * @deprecated Use <code>registerContextMenuFactory()</code> instead.
     */
    @Deprecated
    void registerMenuItem(
            String menuItemCaption,
            IMenuItemHandler menuItemHandler);
}
