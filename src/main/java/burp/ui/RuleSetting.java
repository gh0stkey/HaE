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
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents
        label5 = new JLabel();
        label4 = new JLabel();
        Regex = new JTextField();
        label3 = new JLabel();
        label2 = new JLabel();
        Name = new JTextField();
        ScopeSelect = new JComboBox<>();
        EngineSelect = new JComboBox<>();
        label6 = new JLabel();
        ColorSelect = new JComboBox<>();

        //======== this ========
        setLayout(null);

        //---- label5 ----
        label5.setText("Engine:");
        add(label5);
        label5.setBounds(new Rectangle(new Point(10, 175), label5.getPreferredSize()));

        //---- label4 ----
        label4.setText("Scope:");
        add(label4);
        label4.setBounds(new Rectangle(new Point(10, 135), label4.getPreferredSize()));
        add(Regex);
        Regex.setBounds(70, 50, 265, 30);

        //---- label3 ----
        label3.setText("Regex:");
        add(label3);
        label3.setBounds(new Rectangle(new Point(10, 55), label3.getPreferredSize()));

        //---- label2 ----
        label2.setText("Name:");
        add(label2);
        label2.setBounds(new Rectangle(new Point(10, 15), label2.getPreferredSize()));
        add(Name);
        Name.setBounds(70, 10, 265, 30);

        //---- ScopeSelect ----
        ScopeSelect.setModel(new DefaultComboBoxModel<>(Config.scopeArray));
        add(ScopeSelect);
        ScopeSelect.setBounds(70, 130, 265, ScopeSelect.getPreferredSize().height);

        //---- EngineSelect ----
        EngineSelect.setModel(new DefaultComboBoxModel<>(Config.engineArray));
        add(EngineSelect);
        EngineSelect.setBounds(70, 170, 265, EngineSelect.getPreferredSize().height);

        //---- label7 ----
        label6.setText("Color:");
        add(label6);
        label6.setBounds(new Rectangle(new Point(10, 95), label6.getPreferredSize()));

        //---- ColorSelect ----
        ColorSelect.setModel(new DefaultComboBoxModel<>(Config.colorArray));
        add(ColorSelect);
        ColorSelect.setBounds(70, 90, 265, ColorSelect.getPreferredSize().height);

        {
            // compute preferred size
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
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    private JLabel label5;
    private JLabel label4;
    public JTextField Regex;
    private JLabel label3;
    private JLabel label2;
    public JTextField Name;
    public JComboBox<String> ScopeSelect;
    public JComboBox<String> EngineSelect;
    private JLabel label6;
    public JComboBox<String> ColorSelect;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
}
