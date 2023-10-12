package burp.ui.rule;

import java.awt.*;
import javax.swing.*;
import burp.config.ConfigEntry;

/**
 * @author LinChen & EvilChen
 */

public class RuleSetting extends JPanel {

    public JTextField regexTextField;
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

        addLabel("Regex:", 1, c);
        regexTextField = addTextField(1, c);

        addLabel("Scope:", 2, c);
        scopeComboBox = addComboBox(ConfigEntry.scopeArray, 2, c);

        addLabel("Engine:", 3, c);
        engineComboBox = addComboBox(ConfigEntry.engineArray, 3, c);
        engineComboBox.addActionListener(e -> sensitiveComboBox.setEnabled("nfa".equals(engineComboBox.getSelectedItem().toString())));

        addLabel("Color:", 4, c);
        colorComboBox = addComboBox(ConfigEntry.colorArray, 4, c);

        addLabel("Sensitive:", 5, c);
        sensitiveComboBox = addComboBox(new Boolean[]{true, false}, 5, c);
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
