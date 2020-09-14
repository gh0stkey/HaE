package burp;

/*
 * @(#)IMenuItemHandler.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerMenuItem()</code> to register a custom
 * context menu item.
 *
 * @deprecated Use
 * <code>IContextMenuFactory</code> instead.
 */
@Deprecated
public interface IMenuItemHandler
{
    /**
     * This method is invoked by Burp Suite when the user clicks on a custom
     * menu item which the extension has registered with Burp.
     *
     * @param menuItemCaption The caption of the menu item which was clicked.
     * This parameter enables extensions to provide a single implementation
     * which handles multiple different menu items.
     * @param messageInfo Details of the HTTP message(s) for which the context
     * menu was displayed.
     */
    void menuItemClicked(
            String menuItemCaption,
            IHttpRequestResponse[] messageInfo);
}
