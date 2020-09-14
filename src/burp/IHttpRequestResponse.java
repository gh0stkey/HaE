package burp;

/*
 * @(#)IHttpRequestResponse.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to retrieve and update details about HTTP messages.
 *
 * <b>Note:</b> The setter methods generally can only be used before the message
 * has been processed, and not in read-only contexts. The getter methods
 * relating to response details can only be used after the request has been
 * issued.
 */
public interface IHttpRequestResponse
{
    /**
     * This method is used to retrieve the request message.
     *
     * @return The request message.
     */
    byte[] getRequest();

    /**
     * This method is used to update the request message.
     *
     * @param message The new request message.
     */
    void setRequest(byte[] message);

    /**
     * This method is used to retrieve the response message.
     *
     * @return The response message.
     */
    byte[] getResponse();

    /**
     * This method is used to update the response message.
     *
     * @param message The new response message.
     */
    void setResponse(byte[] message);

    /**
     * This method is used to retrieve the user-annotated comment for this item,
     * if applicable.
     *
     * @return The user-annotated comment for this item, or null if none is set.
     */
    String getComment();

    /**
     * This method is used to update the user-annotated comment for this item.
     *
     * @param comment The comment to be assigned to this item.
     */
    void setComment(String comment);

    /**
     * This method is used to retrieve the user-annotated highlight for this
     * item, if applicable.
     *
     * @return The user-annotated highlight for this item, or null if none is
     * set.
     */
    String getHighlight();

    /**
     * This method is used to update the user-annotated highlight for this item.
     *
     * @param color The highlight color to be assigned to this item. Accepted
     * values are: red, orange, yellow, green, cyan, blue, pink, magenta, gray,
     * or a null String to clear any existing highlight.
     */
    void setHighlight(String color);

    /**
     * This method is used to retrieve the HTTP service for this request /
     * response.
     *
     * @return An
     * <code>IHttpService</code> object containing details of the HTTP service.
     */
    IHttpService getHttpService();

    /**
     * This method is used to update the HTTP service for this request /
     * response.
     *
     * @param httpService An
     * <code>IHttpService</code> object containing details of the new HTTP
     * service.
     */
    void setHttpService(IHttpService httpService);

}
