package burp;

/*
 * @(#)IContextMenuInvocation.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.awt.event.InputEvent;

/**
 * This interface is used when Burp calls into an extension-provided
 * <code>IContextMenuFactory</code> with details of a context menu invocation.
 * The custom context menu factory can query this interface to obtain details of
 * the invocation event, in order to determine what menu items should be
 * displayed.
 */
public interface IContextMenuInvocation
{
    /**
     * Used to indicate that the context menu is being invoked in a request
     * editor.
     */
    static final byte CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
    /**
     * Used to indicate that the context menu is being invoked in a response
     * editor.
     */
    static final byte CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;
    /**
     * Used to indicate that the context menu is being invoked in a non-editable
     * request viewer.
     */
    static final byte CONTEXT_MESSAGE_VIEWER_REQUEST = 2;
    /**
     * Used to indicate that the context menu is being invoked in a non-editable
     * response viewer.
     */
    static final byte CONTEXT_MESSAGE_VIEWER_RESPONSE = 3;
    /**
     * Used to indicate that the context menu is being invoked in the Target
     * site map tree.
     */
    static final byte CONTEXT_TARGET_SITE_MAP_TREE = 4;
    /**
     * Used to indicate that the context menu is being invoked in the Target
     * site map table.
     */
    static final byte CONTEXT_TARGET_SITE_MAP_TABLE = 5;
    /**
     * Used to indicate that the context menu is being invoked in the Proxy
     * history.
     */
    static final byte CONTEXT_PROXY_HISTORY = 6;
    /**
     * Used to indicate that the context menu is being invoked in the Scanner
     * results.
     */
    static final byte CONTEXT_SCANNER_RESULTS = 7;
    /**
     * Used to indicate that the context menu is being invoked in the Intruder
     * payload positions editor.
     */
    static final byte CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8;
    /**
     * Used to indicate that the context menu is being invoked in an Intruder
     * attack results.
     */
    static final byte CONTEXT_INTRUDER_ATTACK_RESULTS = 9;
    /**
     * Used to indicate that the context menu is being invoked in a search
     * results window.
     */
    static final byte CONTEXT_SEARCH_RESULTS = 10;

    /**
     * This method can be used to retrieve the native Java input event that was
     * the trigger for the context menu invocation.
     *
     * @return The <code>InputEvent</code> that was the trigger for the context
     * menu invocation.
     */
    InputEvent getInputEvent();

    /**
     * This method can be used to retrieve the Burp tool within which the
     * context menu was invoked.
     *
     * @return A flag indicating the Burp tool within which the context menu was
     * invoked. Burp tool flags are defined in the
     * <code>IBurpExtenderCallbacks</code> interface.
     */
    int getToolFlag();

    /**
     * This method can be used to retrieve the context within which the menu was
     * invoked.
     *
     * @return An index indicating the context within which the menu was
     * invoked. The indices used are defined within this interface.
     */
    byte getInvocationContext();

    /**
     * This method can be used to retrieve the bounds of the user's selection
     * into the current message, if applicable.
     *
     * @return An int[2] array containing the start and end offsets of the
     * user's selection in the current message. If the user has not made any
     * selection in the current message, both offsets indicate the position of
     * the caret within the editor. If the menu is not being invoked from a
     * message editor, the method returns <code>null</code>.
     */
    int[] getSelectionBounds();

    /**
     * This method can be used to retrieve details of the HTTP requests /
     * responses that were shown or selected by the user when the context menu
     * was invoked.
     *
     * <b>Note:</b> For performance reasons, the objects returned from this
     * method are tied to the originating context of the messages within the
     * Burp UI. For example, if a context menu is invoked on the Proxy intercept
     * panel, then the
     * <code>IHttpRequestResponse</code> returned by this method will reflect
     * the current contents of the interception panel, and this will change when
     * the current message has been forwarded or dropped. If your extension
     * needs to store details of the message for which the context menu has been
     * invoked, then you should query those details from the
     * <code>IHttpRequestResponse</code> at the time of invocation, or you
     * should use
     * <code>IBurpExtenderCallbacks.saveBuffersToTempFiles()</code> to create a
     * persistent read-only copy of the
     * <code>IHttpRequestResponse</code>.
     *
     * @return An array of <code>IHttpRequestResponse</code> objects
     * representing the items that were shown or selected by the user when the
     * context menu was invoked. This method returns <code>null</code> if no
     * messages are applicable to the invocation.
     */
    IHttpRequestResponse[] getSelectedMessages();

    /**
     * This method can be used to retrieve details of the Scanner issues that
     * were selected by the user when the context menu was invoked.
     *
     * @return An array of <code>IScanIssue</code> objects representing the
     * issues that were selected by the user when the context menu was invoked.
     * This method returns <code>null</code> if no Scanner issues are applicable
     * to the invocation.
     */
    IScanIssue[] getSelectedIssues();
}
