package hae.component.rule;

import burp.api.montoya.MontoyaApi;
import hae.Config;
import hae.repository.RuleRepository;
import hae.utils.ConfigLoader;
import hae.utils.rule.RuleProcessor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class Rules extends JTabbedPane {
    private final MontoyaApi api;
    private final RuleRepository ruleRepository;
    private final RuleProcessor ruleProcessor;
    private final JTextField ruleGroupNameTextField;
    private ConfigLoader configLoader;
    private Component tabComponent;
    private int selectedIndex;
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

    public Rules(MontoyaApi api, ConfigLoader configLoader, RuleRepository ruleRepository) {
        this.api = api;
        this.configLoader = configLoader;
        this.ruleRepository = ruleRepository;
        this.ruleProcessor = new RuleProcessor(api, configLoader, ruleRepository);
        this.ruleGroupNameTextField = new JTextField();

        initComponents();
    }

    private void initComponents() {
        reloadRuleGroup();

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
                int index = indexAtLocation(e.getX(), e.getY());
                if (index < 0) {
                    return;
                }

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
                            String title = getTitleAt(index);
                            if ("...".equals(title)) {
                                // 阻止默认的选中行为
                                e.consume();
                                // 直接创建新标签
                                String newTitle = ruleProcessor.newRule();
                                Rule newRule = new Rule(api, configLoader, Config.ruleTemplate, Rules.this, ruleRepository);
                                insertTab(newTitle, null, newRule, null, getTabCount() - 1);
                                setSelectedIndex(getTabCount() - 2);
                            } else {
                                renameTitleActionPerformed.actionPerformed(null);
                            }
                        }
                        break;
                    case MouseEvent.BUTTON3:
                        if (!"...".equals(getTitleAt(index))) {
                            popupMenu.show(e.getComponent(), e.getX(), e.getY());
                        }
                        break;
                    default:
                        break;
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
        ruleRepository.setAll(configLoader.getRules());
        ruleRepository.getAllGroupNames().forEach(i -> addTab(i, new Rule(api, configLoader, ruleRepository.getRulesByGroup(i), this, ruleRepository)));
        addTab("...", null);
    }

    private void deleteRuleGroupActionPerformed(ActionEvent e) {
        if (getTabCount() > 2) {
            int retCode = JOptionPane.showConfirmDialog(this, "Do you want to delete this rule group?", "Info",
                    JOptionPane.YES_NO_OPTION);
            if (retCode == JOptionPane.YES_OPTION) {
                String title = getTitleAt(getSelectedIndex());
                ruleProcessor.deleteRuleGroup(title);
                remove(getSelectedIndex());
                setSelectedIndex(getSelectedIndex() - 1);
            }
        }
    }
}




