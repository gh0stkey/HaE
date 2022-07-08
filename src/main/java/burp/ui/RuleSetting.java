package burp.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import javax.swing.*;
import java.awt.*;
import burp.Config;

/**
 * @author LinChen
 */

public class RuleSetting extends JPanel {
    public RuleSetting() {
        initComponents();
    }

    public void initComponents() {
        sensitiveLabel = new JLabel();
        engineLabel = new JLabel();
        scopeLabel = new JLabel();
        regexTextField = new JTextField();
        regexLabel = new JLabel();
        nameLabel = new JLabel();
        ruleNameTextField = new JTextField();
        scopeComboBox = new JComboBox<>();
        engineComboBox = new JComboBox<>();
        colorLabel = new JLabel();
        colorComboBox = new JComboBox<>();
        sensitiveComboBox = new JComboBox<>();

        setLayout(null);

        engineLabel.setText("Engine:");
        add(engineLabel);
        engineLabel.setBounds(new Rectangle(new Point(10, 175), engineLabel.getPreferredSize()));

        sensitiveLabel.setText("Sensitive:");
        add(sensitiveLabel);
        sensitiveLabel.setBounds(new Rectangle(new Point(10,215), sensitiveLabel.getPreferredSize()));

        scopeLabel.setText("Scope:");
        add(scopeLabel);
        scopeLabel.setBounds(new Rectangle(new Point(10, 135), scopeLabel.getPreferredSize()));
        add(regexTextField);
        regexTextField.setBounds(70, 50, 265, 30);

        regexLabel.setText("Regex:");
        add(regexLabel);
        regexLabel.setBounds(new Rectangle(new Point(10, 55), regexLabel.getPreferredSize()));

        nameLabel.setText("Name:");
        add(nameLabel);
        nameLabel.setBounds(new Rectangle(new Point(10, 15), nameLabel.getPreferredSize()));
        add(ruleNameTextField);
        ruleNameTextField.setBounds(70, 10, 265, 30);

        scopeComboBox.setModel(new DefaultComboBoxModel<>(Config.scopeArray));
        add(scopeComboBox);
        scopeComboBox.setBounds(70, 130, 265, scopeComboBox.getPreferredSize().height);

        engineComboBox.setModel(new DefaultComboBoxModel<>(Config.engineArray));
        engineComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String engineValue = engineComboBox.getSelectedItem().toString();
                if (engineValue.equals("nfa")) {
                    sensitiveComboBox.setEnabled(true);
                } else {
                    sensitiveComboBox.setEnabled(false);
                }
            }
        });
        add(engineComboBox);
        engineComboBox.setBounds(70, 170, 265, engineComboBox.getPreferredSize().height);

        colorLabel.setText("Color:");
        add(colorLabel);
        colorLabel.setBounds(new Rectangle(new Point(10, 95), colorLabel.getPreferredSize()));

        colorComboBox.setModel(new DefaultComboBoxModel<>(Config.colorArray));
        add(colorComboBox);
        colorComboBox.setBounds(70, 90, 265, colorComboBox.getPreferredSize().height);

        sensitiveComboBox.setModel(new DefaultComboBoxModel<>(new Boolean[]{true, false}));
        add(sensitiveComboBox);
        sensitiveComboBox.setBounds(70,210,265,sensitiveComboBox.getPreferredSize().height);

        {
            Dimension preferredSize = new Dimension();
            for(int i = 0; i < getComponentCount(); i++) {
                Rectangle bounds = getComponent(i).getBounds();
                preferredSize.width = Math.max(bounds.x + bounds.width, preferredSize.width);
                preferredSize.height = Math.max(bounds.y + bounds.height, preferredSize.height);
            }
            Insets insets = getInsets();
            preferredSize.width += insets.right;
            preferredSize.height += insets.bottom;
            setMinimumSize(preferredSize);
            setPreferredSize(preferredSize);
        }
    }

    private JLabel engineLabel;
    private JLabel sensitiveLabel;
    private JLabel scopeLabel;
    public JTextField regexTextField;
    private JLabel regexLabel;
    private JLabel nameLabel;
    public JTextField ruleNameTextField;
    public JComboBox<String> scopeComboBox;
    public JComboBox<String> engineComboBox;
    private JLabel colorLabel;
    public JComboBox<String> colorComboBox;
    public JComboBox<Boolean> sensitiveComboBox;
}
