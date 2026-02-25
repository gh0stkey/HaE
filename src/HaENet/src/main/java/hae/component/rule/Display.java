package hae.component.rule;

import hae.AppConstants;

import javax.swing.*;
import java.awt.*;

public class Display extends JPanel {
    public JTextArea firstRegexTextField;
    public JTextArea secondRegexTextField;
    public JTextField formatTextField;
    public JTextField ruleNameTextField;
    public JComboBox<String> scopeComboBox;
    public JComboBox<String> engineComboBox;
    public JComboBox<String> colorComboBox;
    public JComboBox<Boolean> sensitiveComboBox;
    public JTextArea validatorTextField;
    public JTextField validatorTimeoutTextField;
    public JTextField validatorBulkTextField;

    public Display() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.BOTH;

        addLabel("Name:", 0, c);
        ruleNameTextField = addTextField(0, c);

        addLabel("F-Regex:", 1, c);
        firstRegexTextField = addTextArea(1, c);

        addLabel("S-Regex:", 2, c);
        secondRegexTextField = addTextArea(2, c);

        addLabel("Format:", 3, c);
        formatTextField = addTextField(3, c);

        addLabel("Scope:", 4, c);
        scopeComboBox = addComboBox(AppConstants.scope, 4, c);

        addLabel("Engine:", 5, c);
        engineComboBox = addComboBox(AppConstants.engine, 5, c);
        engineComboBox.addActionListener(e -> {
            boolean isNfa = "nfa".equals(engineComboBox.getSelectedItem().toString());
            formatTextField.setEnabled(isNfa);
            formatTextField.setText(isNfa ? formatTextField.getText() : "{0}");
        });

        addLabel("Color:", 6, c);
        colorComboBox = addComboBox(AppConstants.color, 6, c);

        addLabel("Sensitive:", 7, c);
        sensitiveComboBox = addComboBox(new Boolean[]{true, false}, 7, c);

        // Validator group
        JPanel validatorPanel = new JPanel(new GridBagLayout());
        validatorPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(5, 0, 0, 0),
                BorderFactory.createTitledBorder("Validator")
        ));
        GridBagConstraints vc = new GridBagConstraints();
        vc.fill = GridBagConstraints.BOTH;

        vc.gridx = 0;
        vc.gridy = 0;
        validatorPanel.add(new JLabel("Command:"), vc);
        validatorTextField = new JTextArea(3, 35);
        validatorTextField.setLineWrap(true);
        validatorTextField.setWrapStyleWord(true);
        validatorTextField.setFont(UIManager.getFont("TextField.font"));
        JScrollPane cmdScrollPane = new JScrollPane(validatorTextField);
        cmdScrollPane.setBorder(UIManager.getBorder("TextField.border"));
        vc.gridx = 1;
        validatorPanel.add(cmdScrollPane, vc);

        vc.gridx = 0;
        vc.gridy = 1;
        validatorPanel.add(new JLabel("Timeout (ms):"), vc);
        validatorTimeoutTextField = new JTextField(35);
        vc.gridx = 1;
        validatorPanel.add(validatorTimeoutTextField, vc);

        vc.gridx = 0;
        vc.gridy = 2;
        validatorPanel.add(new JLabel("Bulk:"), vc);
        validatorBulkTextField = new JTextField(35);
        vc.gridx = 1;
        validatorPanel.add(validatorBulkTextField, vc);

        c.gridx = 0;
        c.gridy = 8;
        c.gridwidth = 2;
        add(validatorPanel, c);
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

    private JTextArea addTextArea(int y, GridBagConstraints c) {
        JTextArea textArea = new JTextArea(3, 35);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setFont(UIManager.getFont("TextField.font"));
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setBorder(UIManager.getBorder("TextField.border"));
        c.gridx = 1;
        c.gridy = y;
        add(scrollPane, c);
        return textArea;
    }

    private <T> JComboBox<T> addComboBox(T[] items, int y, GridBagConstraints c) {
        JComboBox<T> comboBox = new JComboBox<>(items);
        c.gridx = 1;
        c.gridy = y;
        add(comboBox, c);
        return comboBox;
    }
}
