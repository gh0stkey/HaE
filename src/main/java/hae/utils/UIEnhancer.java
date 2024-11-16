package hae.utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

public class UIEnhancer {
    public static void setTextFieldPlaceholder(JTextField textField, String placeholderText) {
        // 使用客户端属性来存储占位符文本和占位符状态
        textField.putClientProperty("placeholderText", placeholderText);
        textField.putClientProperty("isPlaceholder", true);

        // 设置占位符文本和颜色
        setPlaceholderText(textField);

        textField.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                // 当获得焦点且文本是占位符时，清除文本并更改颜色
                if ((boolean) textField.getClientProperty("isPlaceholder")) {
                    textField.setText("");
                    textField.setForeground(Color.BLACK);
                    textField.putClientProperty("isPlaceholder", false);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                // 当失去焦点且文本为空时，设置占位符文本和颜色
                if (textField.getText().isEmpty()) {
                    setPlaceholderText(textField);
                }
            }
        });
    }

    private static void setPlaceholderText(JTextField textField) {
        String placeholderText = (String) textField.getClientProperty("placeholderText");
        textField.setForeground(Color.GRAY);
        textField.setText(placeholderText);
        textField.putClientProperty("isPlaceholder", true);
    }


}
