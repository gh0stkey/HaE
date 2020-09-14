package burp;

/*
 * @(#)IResponseInfo.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface is used to retrieve key details about an HTTP response.
 * Extensions can obtain an
 * <code>IResponseInfo</code> object for a given response by calling
 * <code>IExtensionHelpers.analyzeResponse()</code>.
 */
public interface IResponseInfo
{
    /**
     * This method is used to obtain the HTTP headers contained in the response.
     *
     * @return The HTTP headers contained in the response.
     */
    List<String> getHeaders();

    /**
     * This method is used to obtain the offset within the response where the
     * message body begins.
     *
     * @return The offset within the response where the message body begins.
     */
    int getBodyOffset();

    /**
     * This method is used to obtain the HTTP status code contained in the
     * response.
     *
     * @return The HTTP status code contained in the response.
     */
    short getStatusCode();

    /**
     * This method is used to obtain details of the HTTP cookies set in the
     * response.
     *
     * @return A list of <code>ICookie</code> objects representing the cookies
     * set in the response, if any.
     */
    List<ICookie> getCookies();

    /**
     * This method is used to obtain the MIME type of the response, as stated in
     * the HTTP headers.
     *
     * @return A textual label for the stated MIME type, or an empty String if
     * this is not known or recognized. The possible labels are the same as
     * those used in the main Burp UI.
     */
    String getStatedMimeType();

    /**
     * This method is used to obtain the MIME type of the response, as inferred
     * from the contents of the HTTP message body.
     *
     * @return A textual label for the inferred MIME type, or an empty String if
     * this is not known or recognized. The possible labels are the same as
     * those used in the main Burp UI.
     */
    String getInferredMimeType();
}
