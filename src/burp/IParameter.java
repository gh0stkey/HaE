package burp;

/*
 * @(#)IParameter.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to hold details about an HTTP request parameter.
 */
public interface IParameter
{
    /**
     * Used to indicate a parameter within the URL query string.
     */
    static final byte PARAM_URL = 0;
    /**
     * Used to indicate a parameter within the message body.
     */
    static final byte PARAM_BODY = 1;
    /**
     * Used to indicate an HTTP cookie.
     */
    static final byte PARAM_COOKIE = 2;
    /**
     * Used to indicate an item of data within an XML structure.
     */
    static final byte PARAM_XML = 3;
    /**
     * Used to indicate the value of a tag attribute within an XML structure.
     */
    static final byte PARAM_XML_ATTR = 4;
    /**
     * Used to indicate the value of a parameter attribute within a multi-part
     * message body (such as the name of an uploaded file).
     */
    static final byte PARAM_MULTIPART_ATTR = 5;
    /**
     * Used to indicate an item of data within a JSON structure.
     */
    static final byte PARAM_JSON = 6;

    /**
     * This method is used to retrieve the parameter type.
     *
     * @return The parameter type. The available types are defined within this
     * interface.
     */
    byte getType();

    /**
     * This method is used to retrieve the parameter name.
     *
     * @return The parameter name.
     */
    String getName();

    /**
     * This method is used to retrieve the parameter value.
     *
     * @return The parameter value.
     */
    String getValue();

    /**
     * This method is used to retrieve the start offset of the parameter name
     * within the HTTP request.
     *
     * @return The start offset of the parameter name within the HTTP request,
     * or -1 if the parameter is not associated with a specific request.
     */
    int getNameStart();

    /**
     * This method is used to retrieve the end offset of the parameter name
     * within the HTTP request.
     *
     * @return The end offset of the parameter name within the HTTP request, or
     * -1 if the parameter is not associated with a specific request.
     */
    int getNameEnd();

    /**
     * This method is used to retrieve the start offset of the parameter value
     * within the HTTP request.
     *
     * @return The start offset of the parameter value within the HTTP request,
     * or -1 if the parameter is not associated with a specific request.
     */
    int getValueStart();

    /**
     * This method is used to retrieve the end offset of the parameter value
     * within the HTTP request.
     *
     * @return The end offset of the parameter value within the HTTP request, or
     * -1 if the parameter is not associated with a specific request.
     */
    int getValueEnd();
}
