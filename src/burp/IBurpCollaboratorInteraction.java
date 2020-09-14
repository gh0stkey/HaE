package burp;

/*
 * @(#)IBurpCollaboratorInteraction.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.Map;

/**
 * This interface represents a network interaction that occurred with the Burp
 * Collaborator server.
 */
public interface IBurpCollaboratorInteraction
{

    /**
     * This method is used to retrieve a property of the interaction. Properties
     * of all interactions are: interaction_id, type, client_ip, and time_stamp.
     * Properties of DNS interactions are: query_type and raw_query. The
     * raw_query value is Base64-encoded. Properties of HTTP interactions are:
     * protocol, request, and response. The request and response values are
     * Base64-encoded.
     *
     * @param name The name of the property to retrieve.
     * @return A string representing the property value, or null if not present.
     */
    String getProperty(String name);

    /**
     * This method is used to retrieve a map containing all properties of the
     * interaction.
     *
     * @return A map containing all properties of the interaction.
     */
    Map<String, String> getProperties();
}
