package burp;

/*
 * @(#)IProxyListener.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerProxyListener()</code> to register a
 * Proxy listener. The listener will be notified of requests and responses being
 * processed by the Proxy tool. Extensions can perform custom analysis or
 * modification of these messages, and control in-UI message interception, by
 * registering a proxy listener.
 */
public interface IProxyListener
{
    /**
     * This method is invoked when an HTTP message is being processed by the
     * Proxy.
     *
     * @param messageIsRequest Indicates whether the HTTP message is a request
     * or a response.
     * @param message An
     * <code>IInterceptedProxyMessage</code> object that extensions can use to
     * query and update details of the message, and control whether the message
     * should be intercepted and displayed to the user for manual review or
     * modification.
     */
    void processProxyMessage(
            boolean messageIsRequest,
            IInterceptedProxyMessage message);
}
