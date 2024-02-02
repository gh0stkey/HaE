package burp.ui.rule;

import java.awt.*;
import javax.swing.*;
import burp.config.ConfigEntry;

/**
 * @author LinChen & EvilChen
 */

public class RuleSetting extends JPanel {
    public JTextField firstRegexTextField;
    public JTextField secondRegexTextField;
    public JTextField formatTextField;
    public JTextField ruleNameTextField;
    public JComboBox<String> scopeComboBox;
    public JComboBox<String> engineComboBox;
    public JComboBox<String> colorComboBox;
    public JComboBox<Boolean> sensitiveComboBox;

    public RuleSetting() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.BOTH;

        addLabel("Name:", 0, c);
        ruleNameTextField = addTextField(0, c);

        addLabel("F-Regex:", 1, c);
        firstRegexTextField = addTextField(1, c);

        addLabel("S-Regex:", 2, c);
        secondRegexTextField = addTextField(2, c);

        addLabel("Format:", 3, c);
        formatTextField = addTextField(3, c);

        addLabel("Scope:", 4, c);
        scopeComboBox = addComboBox(ConfigEntry.scopeArray, 4, c);

        addLabel("Engine:", 5, c);
        engineComboBox = addComboBox(ConfigEntry.engineArray, 5, c);
        engineComboBox.addActionListener(e -> {
            boolean isNfa = "nfa".equals(engineComboBox.getSelectedItem().toString());
            formatTextField.setEnabled(isNfa);
            formatTextField.setText(isNfa ? formatTextField.getText() : "{0}");
        });

        addLabel("Color:", 6, c);
        colorComboBox = addComboBox(ConfigEntry.colorArray, 6, c);

        addLabel("Sensitive:", 7, c);
        sensitiveComboBox = addComboBox(new Boolean[]{true, false}, 7, c);
    }

    private void addLabel(String text, int y, GridBagConstraints c) {
        JLabel label = new JLabel(text);
        c.gridx = 0;
        c.gridy = y;
        add(label, c);
    }

    private JTextField addTextField(int y, GridBagConstraints c) {
        JTextField textField = new JTextField(35);
        c.gridx = 1;
        c.gridy = y;
        add(textField, c);
        return textField;
    }

    private <T> JComboBox<T> addComboBox(T[] items, int y, GridBagConstraints c) {
        JComboBox<T> comboBox = new JComboBox<>(items);
        c.gridx = 1;
        c.gridy = y;
        add(comboBox, c);
        return comboBox;
    }
}
