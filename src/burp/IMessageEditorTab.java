package burp;

/*
 * @(#)IMessageEditorTab.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.awt.Component;

/**
 * Extensions that register an
 * <code>IMessageEditorTabFactory</code> must return instances of this
 * interface, which Burp will use to create custom tabs within its HTTP message
 * editors.
 */
public interface IMessageEditorTab
{
    /**
     * This method returns the caption that should appear on the custom tab when
     * it is displayed. <b>Note:</b> Burp invokes this method once when the tab
     * is first generated, and the same caption will be used every time the tab
     * is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    String getTabCaption();

    /**
     * This method returns the component that should be used as the contents of
     * the custom tab when it is displayed. <b>Note:</b> Burp invokes this
     * method once when the tab is first generated, and the same component will
     * be used every time the tab is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    Component getUiComponent();

    /**
     * The hosting editor will invoke this method before it displays a new HTTP
     * message, so that the custom tab can indicate whether it should be enabled
     * for that message.
     *
     * @param content The message that is about to be displayed, or a zero-length
     * array if the existing message is to be cleared.
     * @param isRequest Indicates whether the message is a request or a
     * response.
     * @return The method should return
     * <code>true</code> if the custom tab is able to handle the specified
     * message, and so will be displayed within the editor. Otherwise, the tab
     * will be hidden while this message is displayed.
     */
    boolean isEnabled(byte[] content, boolean isRequest);

    /**
     * The hosting editor will invoke this method to display a new message or to
     * clear the existing message. This method will only be called with a new
     * message if the tab has already returned
     * <code>true</code> to a call to
     * <code>isEnabled()</code> with the same message details.
     *
     * @param content The message that is to be displayed, or
     * <code>null</code> if the tab should clear its contents and disable any
     * editable controls.
     * @param isRequest Indicates whether the message is a request or a
     * response.
     */
    void setMessage(byte[] content, boolean isRequest);

    /**
     * This method returns the currently displayed message.
     *
     * @return The currently displayed message.
     */
    byte[] getMessage();

    /**
     * This method is used to determine whether the currently displayed message
     * has been modified by the user. The hosting editor will always call
     * <code>getMessage()</code> before calling this method, so any pending
     * edits should be completed within
     * <code>getMessage()</code>.
     *
     * @return The method should return
     * <code>true</code> if the user has modified the current message since it
     * was first displayed.
     */
    boolean isModified();

    /**
     * This method is used to retrieve the data that is currently selected by
     * the user.
     *
     * @return The data that is currently selected by the user. This may be
     * <code>null</code> if no selection is currently made.
     */
    byte[] getSelectedData();
}
