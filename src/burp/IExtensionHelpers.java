package burp;

/*
 * @(#)IExtensionHelpers.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.net.URL;
import java.util.List;

/**
 * This interface contains a number of helper methods, which extensions can use
 * to assist with various common tasks that arise for Burp extensions.
 *
 * Extensions can call <code>IBurpExtenderCallbacks.getHelpers</code> to obtain
 * an instance of this interface.
 */
public interface IExtensionHelpers
{

    /**
     * This method can be used to analyze an HTTP request, and obtain various
     * key details about it.
     *
     * @param request An <code>IHttpRequestResponse</code> object containing the
     * request to be analyzed.
     * @return An <code>IRequestInfo</code> object that can be queried to obtain
     * details about the request.
     */
    IRequestInfo analyzeRequest(IHttpRequestResponse request);

    /**
     * This method can be used to analyze an HTTP request, and obtain various
     * key details about it.
     *
     * @param httpService The HTTP service associated with the request. This is
     * optional and may be <code>null</code>, in which case the resulting
     * <code>IRequestInfo</code> object will not include the full request URL.
     * @param request The request to be analyzed.
     * @return An <code>IRequestInfo</code> object that can be queried to obtain
     * details about the request.
     */
    IRequestInfo analyzeRequest(IHttpService httpService, byte[] request);

    /**
     * This method can be used to analyze an HTTP request, and obtain various
     * key details about it. The resulting <code>IRequestInfo</code> object will
     * not include the full request URL. To obtain the full URL, use one of the
     * other overloaded <code>analyzeRequest()</code> methods.
     *
     * @param request The request to be analyzed.
     * @return An <code>IRequestInfo</code> object that can be queried to obtain
     * details about the request.
     */
    IRequestInfo analyzeRequest(byte[] request);

    /**
     * This method can be used to analyze an HTTP response, and obtain various
     * key details about it.
     *
     * @param response The response to be analyzed.
     * @return An <code>IResponseInfo</code> object that can be queried to
     * obtain details about the response.
     */
    IResponseInfo analyzeResponse(byte[] response);

    /**
     * This method can be used to retrieve details of a specified parameter
     * within an HTTP request. <b>Note:</b> Use <code>analyzeRequest()</code> to
     * obtain details of all parameters within the request.
     *
     * @param request The request to be inspected for the specified parameter.
     * @param parameterName The name of the parameter to retrieve.
     * @return An <code>IParameter</code> object that can be queried to obtain
     * details about the parameter, or <code>null</code> if the parameter was
     * not found.
     */
    IParameter getRequestParameter(byte[] request, String parameterName);

    /**
     * This method can be used to URL-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    String urlDecode(String data);

    /**
     * This method can be used to URL-encode the specified data. Any characters
     * that do not need to be encoded within HTTP requests are not encoded.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    String urlEncode(String data);

    /**
     * This method can be used to URL-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    byte[] urlDecode(byte[] data);

    /**
     * This method can be used to URL-encode the specified data. Any characters
     * that do not need to be encoded within HTTP requests are not encoded.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    byte[] urlEncode(byte[] data);

    /**
     * This method can be used to Base64-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    byte[] base64Decode(String data);

    /**
     * This method can be used to Base64-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    byte[] base64Decode(byte[] data);

    /**
     * This method can be used to Base64-encode the specified data.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    String base64Encode(String data);

    /**
     * This method can be used to Base64-encode the specified data.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    String base64Encode(byte[] data);

    /**
     * This method can be used to convert data from String form into an array of
     * bytes. The conversion does not reflect any particular character set, and
     * a character with the hex representation 0xWXYZ will always be converted
     * into a byte with the representation 0xYZ. It performs the opposite
     * conversion to the method <code>bytesToString()</code>, and byte-based
     * data that is converted to a String and back again using these two methods
     * is guaranteed to retain its integrity (which may not be the case with
     * conversions that reflect a given character set).
     *
     * @param data The data to be converted.
     * @return The converted data.
     */
    byte[] stringToBytes(String data);

    /**
     * This method can be used to convert data from an array of bytes into
     * String form. The conversion does not reflect any particular character
     * set, and a byte with the representation 0xYZ will always be converted
     * into a character with the hex representation 0x00YZ. It performs the
     * opposite conversion to the method <code>stringToBytes()</code>, and
     * byte-based data that is converted to a String and back again using these
     * two methods is guaranteed to retain its integrity (which may not be the
     * case with conversions that reflect a given character set).
     *
     * @param data The data to be converted.
     * @return The converted data.
     */
    String bytesToString(byte[] data);

    /**
     * This method searches a piece of data for the first occurrence of a
     * specified pattern. It works on byte-based data in a way that is similar
     * to the way the native Java method <code>String.indexOf()</code> works on
     * String-based data.
     *
     * @param data The data to be searched.
     * @param pattern The pattern to be searched for.
     * @param caseSensitive Flags whether or not the search is case-sensitive.
     * @param from The offset within <code>data</code> where the search should
     * begin.
     * @param to The offset within <code>data</code> where the search should
     * end.
     * @return The offset of the first occurrence of the pattern within the
     * specified bounds, or -1 if no match is found.
     */
    int indexOf(byte[] data,
            byte[] pattern,
            boolean caseSensitive,
            int from,
            int to);

    /**
     * This method builds an HTTP message containing the specified headers and
     * message body. If applicable, the Content-Length header will be added or
     * updated, based on the length of the body.
     *
     * @param headers A list of headers to include in the message.
     * @param body The body of the message, of <code>null</code> if the message
     * has an empty body.
     * @return The resulting full HTTP message.
     */
    byte[] buildHttpMessage(List<String> headers, byte[] body);

    /**
     * This method creates a GET request to the specified URL. The headers used
     * in the request are determined by the Request headers settings as
     * configured in Burp Spider's options.
     *
     * @param url The URL to which the request should be made.
     * @return A request to the specified URL.
     */
    byte[] buildHttpRequest(URL url);

    /**
     * This method adds a new parameter to an HTTP request, and if appropriate
     * updates the Content-Length header.
     *
     * @param request The request to which the parameter should be added.
     * @param parameter An <code>IParameter</code> object containing details of
     * the parameter to be added. Supported parameter types are:
     * <code>PARAM_URL</code>, <code>PARAM_BODY</code> and
     * <code>PARAM_COOKIE</code>.
     * @return A new HTTP request with the new parameter added.
     */
    byte[] addParameter(byte[] request, IParameter parameter);

    /**
     * This method removes a parameter from an HTTP request, and if appropriate
     * updates the Content-Length header.
     *
     * @param request The request from which the parameter should be removed.
     * @param parameter An <code>IParameter</code> object containing details of
     * the parameter to be removed. Supported parameter types are:
     * <code>PARAM_URL</code>, <code>PARAM_BODY</code> and
     * <code>PARAM_COOKIE</code>.
     * @return A new HTTP request with the parameter removed.
     */
    byte[] removeParameter(byte[] request, IParameter parameter);

    /**
     * This method updates the value of a parameter within an HTTP request, and
     * if appropriate updates the Content-Length header. <b>Note:</b> This
     * method can only be used to update the value of an existing parameter of a
     * specified type. If you need to change the type of an existing parameter,
     * you should first call <code>removeParameter()</code> to remove the
     * parameter with the old type, and then call <code>addParameter()</code> to
     * add a parameter with the new type.
     *
     * @param request The request containing the parameter to be updated.
     * @param parameter An <code>IParameter</code> object containing details of
     * the parameter to be updated. Supported parameter types are:
     * <code>PARAM_URL</code>, <code>PARAM_BODY</code> and
     * <code>PARAM_COOKIE</code>.
     * @return A new HTTP request with the parameter updated.
     */
    byte[] updateParameter(byte[] request, IParameter parameter);

    /**
     * This method can be used to toggle a request's method between GET and
     * POST. Parameters are relocated between the URL query string and message
     * body as required, and the Content-Length header is created or removed as
     * applicable.
     *
     * @param request The HTTP request whose method should be toggled.
     * @return A new HTTP request using the toggled method.
     */
    byte[] toggleRequestMethod(byte[] request);

    /**
     * This method constructs an <code>IHttpService</code> object based on the
     * details provided.
     *
     * @param host The HTTP service host.
     * @param port The HTTP service port.
     * @param protocol The HTTP service protocol.
     * @return An <code>IHttpService</code> object based on the details
     * provided.
     */
    IHttpService buildHttpService(String host, int port, String protocol);

    /**
     * This method constructs an <code>IHttpService</code> object based on the
     * details provided.
     *
     * @param host The HTTP service host.
     * @param port The HTTP service port.
     * @param useHttps Flags whether the HTTP service protocol is HTTPS or HTTP.
     * @return An <code>IHttpService</code> object based on the details
     * provided.
     */
    IHttpService buildHttpService(String host, int port, boolean useHttps);

    /**
     * This method constructs an <code>IParameter</code> object based on the
     * details provided.
     *
     * @param name The parameter name.
     * @param value The parameter value.
     * @param type The parameter type, as defined in the <code>IParameter</code>
     * interface.
     * @return An <code>IParameter</code> object based on the details provided.
     */
    IParameter buildParameter(String name, String value, byte type);

    /**
     * This method constructs an <code>IScannerInsertionPoint</code> object
     * based on the details provided. It can be used to quickly create a simple
     * insertion point based on a fixed payload location within a base request.
     *
     * @param insertionPointName The name of the insertion point.
     * @param baseRequest The request from which to build scan requests.
     * @param from The offset of the start of the payload location.
     * @param to The offset of the end of the payload location.
     * @return An <code>IScannerInsertionPoint</code> object based on the
     * details provided.
     */
    IScannerInsertionPoint makeScannerInsertionPoint(
            String insertionPointName,
            byte[] baseRequest,
            int from,
            int to);

    /**
     * This method analyzes one or more responses to identify variations in a
     * number of attributes and returns an <code>IResponseVariations</code>
     * object that can be queried to obtain details of the variations.
     *
     * @param responses The responses to analyze.
     * @return An <code>IResponseVariations</code> object representing the
     * variations in the responses.
     */
    IResponseVariations analyzeResponseVariations(byte[]... responses);

    /**
     * This method analyzes one or more responses to identify the number of
     * occurrences of the specified keywords and returns an
     * <code>IResponseKeywords</code> object that can be queried to obtain
     * details of the number of occurrences of each keyword.
     *
     * @param keywords The keywords to look for.
     * @param responses The responses to analyze.
     * @return An <code>IResponseKeywords</code> object representing the counts
     * of the keywords appearing in the responses.
     */
    IResponseKeywords analyzeResponseKeywords(List<String> keywords, byte[]... responses);
}
