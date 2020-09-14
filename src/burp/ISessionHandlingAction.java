package burp;

/*
 * @(#)ISessionHandlingAction.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerSessionHandlingAction()</code> to
 * register a custom session handling action. Each registered action will be
 * available within the session handling rule UI for the user to select as a
 * rule action. Users can choose to invoke an action directly in its own right,
 * or following execution of a macro.
 */
public interface ISessionHandlingAction
{
    /**
     * This method is used by Burp to obtain the name of the session handling
     * action. This will be displayed as an option within the session handling
     * rule editor when the user selects to execute an extension-provided
     * action.
     *
     * @return The name of the action.
     */
    String getActionName();

    /**
     * This method is invoked when the session handling action should be
     * executed. This may happen as an action in its own right, or as a
     * sub-action following execution of a macro.
     *
     * @param currentRequest The base request that is currently being processed.
     * The action can query this object to obtain details about the base
     * request. It can issue additional requests of its own if necessary, and
     * can use the setter methods on this object to update the base request.
     * @param macroItems If the action is invoked following execution of a
     * macro, this parameter contains the result of executing the macro.
     * Otherwise, it is
     * <code>null</code>. Actions can use the details of the macro items to
     * perform custom analysis of the macro to derive values of non-standard
     * session handling tokens, etc.
     */
    void performAction(
            IHttpRequestResponse currentRequest,
            IHttpRequestResponse[] macroItems);
}
