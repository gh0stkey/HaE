package burp;

/*
 * @(#)IHttpRequestResponsePersisted.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used for an
 * <code>IHttpRequestResponse</code> object whose request and response messages
 * have been saved to temporary files using
 * <code>IBurpExtenderCallbacks.saveBuffersToTempFiles()</code>.
 */
public interface IHttpRequestResponsePersisted extends IHttpRequestResponse
{
    /**
     * This method is deprecated and no longer performs any action.
     */
    @Deprecated
    void deleteTempFiles();
}
