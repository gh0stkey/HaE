package burp;

/*
 * @(#)IHttpRequestResponseWithMarkers.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface is used for an
 * <code>IHttpRequestResponse</code> object that has had markers applied.
 * Extensions can create instances of this interface using
 * <code>IBurpExtenderCallbacks.applyMarkers()</code>, or provide their own
 * implementation. Markers are used in various situations, such as specifying
 * Intruder payload positions, Scanner insertion points, and highlights in
 * Scanner issues.
 */
public interface IHttpRequestResponseWithMarkers extends IHttpRequestResponse
{
    /**
     * This method returns the details of the request markers.
     *
     * @return A list of index pairs representing the offsets of markers for the
     * request message. Each item in the list is an int[2] array containing the
     * start and end offsets for the marker. The method may return
     * <code>null</code> if no request markers are defined.
     */
    List<int[]> getRequestMarkers();

    /**
     * This method returns the details of the response markers.
     *
     * @return A list of index pairs representing the offsets of markers for the
     * response message. Each item in the list is an int[2] array containing the
     * start and end offsets for the marker. The method may return
     * <code>null</code> if no response markers are defined.
     */
    List<int[]> getResponseMarkers();
}
