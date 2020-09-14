package burp;

/*
 * @(#)IResponseVariations.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface is used to represent variations between a number HTTP
 * responses, according to various attributes.
 */
public interface IResponseVariations
{

    /**
     * This method is used to obtain the list of attributes that vary between
     * the analyzed responses.
     *
     * @return The attributes that vary between the analyzed responses.
     */
    List<String> getVariantAttributes();

    /**
     * This method is used to obtain the list of attributes that do not vary
     * between the analyzed responses.
     *
     * @return The attributes that do not vary between the analyzed responses.
     */
    List<String> getInvariantAttributes();

    /**
     * This method is used to obtain the value of an individual attribute in a
     * response. Note that the values of some attributes are intrinsically
     * meaningful (e.g. a word count) while the values of others are less so
     * (e.g. a checksum of the HTML tag names).
     *
     * @param attributeName The name of the attribute whose value will be
     * retrieved. Extension authors can obtain the list of supported attributes
     * by generating an <code>IResponseVariations</code> object for a single
     * response and calling
     * <code>IResponseVariations.getInvariantAttributes()</code>.
     * @param responseIndex The index of the response. Note that responses are
     * indexed from zero in the order they were originally supplied to the
     * <code>IExtensionHelpers.analyzeResponseVariations()</code> and
     * <code>IResponseVariations.updateWith()</code> methods.
     * @return The value of the specified attribute for the specified response.
     */
    int getAttributeValue(String attributeName, int responseIndex);

    /**
     * This method is used to update the analysis based on additional responses.
     *
     * @param responses The new responses to include in the analysis.
     */
    void updateWith(byte[]... responses);
}
