package burp;

/*
 * @(#)IResponseKeywords.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.List;

/**
 * This interface is used to represent the counts of keywords appearing in a
 * number of HTTP responses.
 */
public interface IResponseKeywords
{

    /**
     * This method is used to obtain the list of keywords whose counts vary
     * between the analyzed responses.
     *
     * @return The keywords whose counts vary between the analyzed responses.
     */
    List<String> getVariantKeywords();

    /**
     * This method is used to obtain the list of keywords whose counts do not
     * vary between the analyzed responses.
     *
     * @return The keywords whose counts do not vary between the analyzed
     * responses.
     */
    List<String> getInvariantKeywords();

    /**
     * This method is used to obtain the number of occurrences of an individual
     * keyword in a response.
     *
     * @param keyword The keyword whose count will be retrieved.
     * @param responseIndex The index of the response. Note responses are
     * indexed from zero in the order they were originally supplied to the
     * <code>IExtensionHelpers.analyzeResponseKeywords()</code> and
     * <code>IResponseKeywords.updateWith()</code> methods.
     * @return The number of occurrences of the specified keyword for the
     * specified response.
     */
    int getKeywordCount(String keyword, int responseIndex);

    /**
     * This method is used to update the analysis based on additional responses.
     *
     * @param responses The new responses to include in the analysis.
     */
    void updateWith(byte[]... responses);
}
