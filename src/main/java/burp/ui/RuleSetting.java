package burp.ui;

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
        engineLabel = new JLabel();
        scopeLabel = new JLabel();
        regexTextField = new JTextField();
        regexLabel = new JLabel();
        nameLabel = new JLabel();
        Name = new JTextField();
        scopeComboBox = new JComboBox<>();
        engineComboBox = new JComboBox<>();
        colorLabel = new JLabel();
        colorComboBox = new JComboBox<>();

        setLayout(null);

        engineLabel.setText("Engine:");
        add(engineLabel);
        engineLabel.setBounds(new Rectangle(new Point(10, 175), engineLabel.getPreferredSize()));

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
        add(Name);
        Name.setBounds(70, 10, 265, 30);

        scopeComboBox.setModel(new DefaultComboBoxModel<>(Config.scopeArray));
        add(scopeComboBox);
        scopeComboBox.setBounds(70, 130, 265, scopeComboBox.getPreferredSize().height);

        engineComboBox.setModel(new DefaultComboBoxModel<>(Config.engineArray));
        add(engineComboBox);
        engineComboBox.setBounds(70, 170, 265, engineComboBox.getPreferredSize().height);

        colorLabel.setText("Color:");
        add(colorLabel);
        colorLabel.setBounds(new Rectangle(new Point(10, 95), colorLabel.getPreferredSize()));

        colorComboBox.setModel(new DefaultComboBoxModel<>(Config.colorArray));
        add(colorComboBox);
        colorComboBox.setBounds(70, 90, 265, colorComboBox.getPreferredSize().height);

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
    private JLabel scopeLabel;
    public JTextField regexTextField;
    private JLabel regexLabel;
    private JLabel nameLabel;
    public JTextField Name;
    public JComboBox<String> scopeComboBox;
    public JComboBox<String> engineComboBox;
    private JLabel colorLabel;
    public JComboBox<String> colorComboBox;
}
