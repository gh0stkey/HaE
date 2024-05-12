package hae.component.rule;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import hae.utils.config.ConfigLoader;
import hae.utils.rule.RuleProcessor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class Rules extends JTabbedPane {
    private final MontoyaApi api;
    private ConfigLoader configLoader;
    private final RuleProcessor ruleProcessor;
    private final JTextField ruleGroupNameTextField;

    private Component tabComponent;
    private int selectedIndex;

    public Rules(MontoyaApi api, ConfigLoader configLoader) {
        this.api = api;
        this.configLoader = configLoader;
        this.ruleProcessor = new RuleProcessor(api, configLoader);
        this.ruleGroupNameTextField = new JTextField();

        initComponents();
    }

    private void initComponents() {
        reloadRuleGroup();

        JTabbedPane tabbedPane = this;

        JMenuItem deleteMenuItem = new JMenuItem("Delete");
        JPopupMenu popupMenu = new JPopupMenu();
        popupMenu.add(deleteMenuItem);

        deleteMenuItem.addActionListener(this::deleteRuleGroupActionPerformed);

        ruleGroupNameTextField.setBorder(BorderFactory.createEmptyBorder());
        ruleGroupNameTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                renameTitleActionPerformed.actionPerformed(null);
            }
        });

        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int index = getSelectedIndex();
                Rectangle r = getBoundsAt(index);
                if (r.contains(e.getPoint()) && index >= 0) {
                    switch (e.getButton()) {
                        case MouseEvent.BUTTON1:
                            if (e.getClickCount() == 2) {
                                selectedIndex = index;
                                tabComponent = getTabComponentAt(selectedIndex);
                                String ruleGroupName = getTitleAt(selectedIndex);

                                if (!"...".equals(ruleGroupName)) {
                                    setTabComponentAt(selectedIndex, ruleGroupNameTextField);
                                    ruleGroupNameTextField.setVisible(true);
                                    ruleGroupNameTextField.setText(ruleGroupName);
                                    ruleGroupNameTextField.selectAll();
                                    ruleGroupNameTextField.requestFocusInWindow();
                                    ruleGroupNameTextField.setMinimumSize(ruleGroupNameTextField.getPreferredSize());
                                }
                            } else if (e.getClickCount() == 1) {
                                if ("...".equals(getTitleAt(getSelectedIndex()))) {
                                    String title = ruleProcessor.newRule();
                                    Rule newRule = new Rule(api, configLoader, Config.ruleTemplate, tabbedPane);
                                    insertTab(title, null, newRule, null, getTabCount() - 1);
                                    setSelectedIndex(getTabCount() - 2);
                                } else {
                                    renameTitleActionPerformed.actionPerformed(null);
                                }
                            }
                            break;
                        case MouseEvent.BUTTON3:
                            if (!"...".equals(getTitleAt(getSelectedIndex()))) {
                                popupMenu.show(e.getComponent(), e.getX(), e.getY());
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
        });


        InputMap im = ruleGroupNameTextField.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = ruleGroupNameTextField.getActionMap();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancel");
        am.put("cancel", cancelActionPerformed);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "rename");
        am.put("rename", renameTitleActionPerformed);
    }

    public void reloadRuleGroup() {
        removeAll();

        this.configLoader = new ConfigLoader(api);
        Config.globalRules.keySet().forEach(i -> addTab(i, new Rule(api, configLoader, hae.Config.globalRules.get(i), this)));
        addTab("...", null);
    }

    private void deleteRuleGroupActionPerformed(ActionEvent e) {
        if (getTabCount() > 2) {
            int retCode = JOptionPane.showConfirmDialog(null, "Do you want to delete this rule group?", "Info",
                    JOptionPane.YES_NO_OPTION);
            if (retCode == JOptionPane.YES_OPTION) {
                String title = getTitleAt(getSelectedIndex());
                ruleProcessor.deleteRuleGroup(title);
                remove(getSelectedIndex());
                setSelectedIndex(getSelectedIndex() - 1);
            }
        }
    }

    private final Action renameTitleActionPerformed = new AbstractAction() {
        @Override
        public void actionPerformed(ActionEvent e) {
            String title = ruleGroupNameTextField.getText();
            if (!title.isEmpty() && selectedIndex >= 0) {
                String oldName = getTitleAt(selectedIndex);
                setTitleAt(selectedIndex, title);

                if (!oldName.equals(title)) {
                    ruleProcessor.renameRuleGroup(oldName, title);
                }
            }
            cancelActionPerformed.actionPerformed(null);
        }
    };

    private final Action cancelActionPerformed = new AbstractAction() {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (selectedIndex >= 0) {
                setTabComponentAt(selectedIndex, tabComponent);

                ruleGroupNameTextField.setVisible(false);
                ruleGroupNameTextField.setPreferredSize(null);
                selectedIndex = -1;
                tabComponent = null;

                requestFocusInWindow();
            }
        }
    };
}




