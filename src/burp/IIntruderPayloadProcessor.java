package burp;

/*
 * @(#)IIntruderPayloadProcessor.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * <code>IBurpExtenderCallbacks.registerIntruderPayloadProcessor()</code> to
 * register a custom Intruder payload processor.
 */
public interface IIntruderPayloadProcessor
{
    /**
     * This method is used by Burp to obtain the name of the payload processor.
     * This will be displayed as an option within the Intruder UI when the user
     * selects to use an extension-provided payload processor.
     *
     * @return The name of the payload processor.
     */
    String getProcessorName();

    /**
     * This method is invoked by Burp each time the processor should be applied
     * to an Intruder payload.
     *
     * @param currentPayload The value of the payload to be processed.
     * @param originalPayload The value of the original payload prior to
     * processing by any already-applied processing rules.
     * @param baseValue The base value of the payload position, which will be
     * replaced with the current payload.
     * @return The value of the processed payload. This may be
     * <code>null</code> to indicate that the current payload should be skipped,
     * and the attack will move directly to the next payload.
     */
    byte[] processPayload(
            byte[] currentPayload,
            byte[] originalPayload,
            byte[] baseValue);
}
