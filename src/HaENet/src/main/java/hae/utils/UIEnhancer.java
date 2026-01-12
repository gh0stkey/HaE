package hae.utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

public class UIEnhancer {
    public static void setTextFieldPlaceholder(JTextField textField, String placeholderText) {
        // 存储占位符文本
        textField.putClientProperty("placeholderText", placeholderText);
        textField.putClientProperty("isPlaceholder", true);

        updatePlaceholderText(textField);

        textField.addPropertyChangeListener("background", evt -> {
            updateForeground(textField);
        });

        textField.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (Boolean.TRUE.equals(textField.getClientProperty("isPlaceholder"))) {
                    textField.putClientProperty("isPlaceholder", false);
                    updateForeground(textField);

                    textField.setText("");
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (textField.getText().isEmpty()) {
                    updatePlaceholderText(textField);
                }
            }
        });

        textField.addPropertyChangeListener("text", evt -> {
            if (Boolean.TRUE.equals(textField.getClientProperty("isPlaceholder"))) {
                if (!textField.getText().isEmpty()) {
                    textField.putClientProperty("isPlaceholder", false);
                    updateForeground(textField);
                }
            } else {
                if (textField.getText().isEmpty()) {
                    updatePlaceholderText(textField);
                }
            }
        });
    }

    private static void updatePlaceholderText(JTextField textField) {
        String placeholderText = (String) textField.getClientProperty("placeholderText");
        textField.putClientProperty("isPlaceholder", true);
        textField.setText(placeholderText);
        textField.setForeground(Color.GRAY);
    }

    private static void updateForeground(JTextField textField) {
        Color bg = textField.getBackground();
        Color fg = isDarkColor(bg) ? Color.WHITE : Color.BLACK;

        if (!Boolean.TRUE.equals(textField.getClientProperty("isPlaceholder"))) {
            textField.setForeground(fg);
            textField.putClientProperty("isPlaceholder", false);
        }
    }

    public static boolean isDarkColor(Color color) {
        double brightness = 0.299 * color.getRed()
                + 0.587 * color.getGreen()
                + 0.114 * color.getBlue();
        return brightness < 128;
    }

    public static boolean hasUserInput(JTextField field) {
        Object prop = field.getClientProperty("isPlaceholder");
        return prop instanceof Boolean && !((Boolean) prop);
    }
}