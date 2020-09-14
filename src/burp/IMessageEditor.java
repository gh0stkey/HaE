package burp;

/*
 * @(#)IMessageEditor.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.awt.Component;

/**
 * This interface is used to provide extensions with an instance of Burp's HTTP
 * message editor, for the extension to use in its own UI. Extensions should
 * call <code>IBurpExtenderCallbacks.createMessageEditor()</code> to obtain an
 * instance of this interface.
 */
public interface IMessageEditor
{

    /**
     * This method returns the UI component of the editor, for extensions to add
     * to their own UI.
     *
     * @return The UI component of the editor.
     */
    Component getComponent();

    /**
     * This method is used to display an HTTP message in the editor.
     *
     * @param message The HTTP message to be displayed.
     * @param isRequest Flags whether the message is an HTTP request or
     * response.
     */
    void setMessage(byte[] message, boolean isRequest);

    /**
     * This method is used to retrieve the currently displayed message, which
     * may have been modified by the user.
     *
     * @return The currently displayed HTTP message.
     */
    byte[] getMessage();

    /**
     * This method is used to determine whether the current message has been
     * modified by the user.
     *
     * @return An indication of whether the current message has been modified by
     * the user since it was first displayed.
     */
    boolean isMessageModified();

    /**
     * This method returns the data that is currently selected by the user.
     *
     * @return The data that is currently selected by the user, or
     * <code>null</code> if no selection is made.
     */
    byte[] getSelectedData();

    /**
     * This method can be used to retrieve the bounds of the user's selection
     * into the displayed message, if applicable.
     *
     * @return An int[2] array containing the start and end offsets of the
     * user's selection within the displayed message. If the user has not made
     * any selection in the current message, both offsets indicate the position
     * of the caret within the editor. For some editor views, the concept of
     * selection within the message does not apply, in which case this method
     * returns null.
     */
    int[] getSelectionBounds();
}
