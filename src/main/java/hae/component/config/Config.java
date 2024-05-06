package hae.component.config;

import burp.api.montoya.MontoyaApi;
import hae.component.rule.Rules;
import hae.utils.config.ConfigLoader;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

public class Config extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final Rules rules;

    public Config(MontoyaApi api, ConfigLoader configLoader, Rules rules) {
        this.api = api;
        this.configLoader = configLoader;
        this.rules = rules;

        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        ((GridBagLayout) getLayout()).columnWidths = new int[] {0, 0, 0, 0, 0};
        ((GridBagLayout) getLayout()).rowHeights = new int[] {0, 0, 0};
        ((GridBagLayout) getLayout()).columnWeights = new double[] {0.0, 1.0, 0.0, 0.0, 1.0E-4};
        ((GridBagLayout) getLayout()).rowWeights = new double[] {0.0, 0.0, 1.0E-4};

        JLabel rulesFilePathLabel = new JLabel("Rules Path:");
        JTextField rulesFilePathTextField = new JTextField();
        JButton onlineUpdateButton = new JButton("Update");
        JLabel excludeSuffixLabel = new JLabel("Exclude Suffix:");
        JTextField excludeSuffixTextField = new JTextField();
        JButton excludeSuffixSaveButton = new JButton("Save");
        JButton reloadButton = new JButton("Reload");

        rulesFilePathTextField.setEditable(false);

        onlineUpdateButton.addActionListener(this::onlineUpdateActionPerformed);
        excludeSuffixSaveButton.addActionListener(e -> excludeSuffixSaveActionPerformed(e, excludeSuffixTextField.getText()));
        reloadButton.addActionListener(this::reloadActionPerformed);

        rulesFilePathTextField.setText(configLoader.getRulesFilePath());
        excludeSuffixTextField.setText(configLoader.getExcludeSuffix());

        add(rulesFilePathTextField, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(5, 0, 5, 5), 0, 0));
        add(rulesFilePathLabel, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.VERTICAL,
                new Insets(5, 5, 5, 5), 0, 0));
        add(onlineUpdateButton, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(5, 0, 5, 5), 0, 0));
        add(reloadButton, new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(5, 0, 5, 5), 0, 0));
        add(excludeSuffixLabel, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.SOUTHWEST, GridBagConstraints.NONE,
                new Insets(0, 5, 5, 5), 0, 0));
        add(excludeSuffixTextField, new GridBagConstraints(1, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.SOUTH, GridBagConstraints.HORIZONTAL,
                new Insets(0, 0, 0, 5), 0, 0));
        add(excludeSuffixSaveButton, new GridBagConstraints(2, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.SOUTH, GridBagConstraints.HORIZONTAL,
                new Insets(0, 0, 0, 5), 0, 0));
    }

    private void onlineUpdateActionPerformed(ActionEvent e) {
        // 添加提示框防止用户误触导致配置更新
        int retCode = JOptionPane.showConfirmDialog(null, "Do you want to update rules?", "Info", JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            configLoader.initRules();
            reloadActionPerformed(null);
        }
    }

    private void excludeSuffixSaveActionPerformed(ActionEvent e, String suffix) {
        if (!suffix.equals(configLoader.getExcludeSuffix()) && !suffix.isEmpty()) {
            configLoader.setExcludeSuffix(suffix);
        }
    }

    private void reloadActionPerformed(ActionEvent e) {
        rules.reloadRuleGroup();
    }
}
