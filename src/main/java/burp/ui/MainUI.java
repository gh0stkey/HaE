package burp.ui;

import burp.config.ConfigEntry;
import burp.config.ConfigLoader;
import burp.rule.RuleProcessor;
import burp.rule.utils.RuleTool;
import burp.ui.board.Databoard;
import burp.ui.board.MessagePanel;
import burp.ui.rule.RulePane;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.*;
import java.util.Map;

/**
 * @author LinChen && EvilChen
 */

public class MainUI extends JPanel {
    private final ConfigLoader loadConn = new ConfigLoader();
    private MessagePanel messagePanel;

    public MainUI(MessagePanel messagePanel) {
        this.messagePanel = messagePanel;
        databoardPanel = new Databoard(this.messagePanel);
        initComponents();
    }

    public void closeTabActionPerformed(ActionEvent e) {
        if (ruleTabbedPane.getTabCount() > 2 && ruleTabbedPane.getSelectedIndex() != 0) {
            String title = ruleTabbedPane.getTitleAt(ruleTabbedPane.getSelectedIndex());
            new RuleProcessor().deleteRuleGroup(title);
            ruleTabbedPane.remove(ruleTabbedPane.getSelectedIndex());
            ruleTabbedPane.setSelectedIndex(ruleTabbedPane.getSelectedIndex() - 1);
        }
    }

    private void onlineUpdateActionPerformed(ActionEvent e) {
        // 添加提示框防止用户误触导致配置更新
        int retCode = JOptionPane.showConfirmDialog(null, "Do you want to update config?", "Info",
                JOptionPane.YES_NO_OPTION);
        if (retCode == JOptionPane.YES_OPTION) {
            String rulesFilePath = rulesPathTextField.getText();
            RuleTool rt = new RuleTool(rulesFilePath);
            rt.getRulesFromSite();
            new ConfigLoader();
            reloadRule();
        }
    }

    private void reloadRule(){
        ruleTabbedPane.removeAll();
        ruleSwitch.setListen(false);
        Map<String,Object[][]> rules = ConfigLoader.getRules();
        rules.keySet().forEach(
                i -> ruleTabbedPane.addTab(
                        i,
                        new RulePane(rules.get(i), ruleTabbedPane)
                )

        );
        ruleTabbedPane.addTab("...", new JLabel());
        ruleSwitch.setListen(true);
    }

    private void reloadActionPerformed(ActionEvent e) {
        reloadRule();
    }

    private void excludeSuffixSaveActionPerformed(ActionEvent e) {
        ConfigLoader loadCon = new ConfigLoader();
        loadCon.setExcludeSuffix(excludeSuffixTextField.getText());
    }
    private void initComponents() {
        JTabbedPane mainTabbedPane = new JTabbedPane();
        ruleTabbedPane = new JTabbedPane();
        JPanel rulePanel = new JPanel();
        rulesPathTextField = new JTextField();
        JLabel rulesPathLabel = new JLabel();
        JButton onlineUpdateButton = new JButton();
        JButton reloadButton = new JButton();
        JLabel excludeSuffixLabel = new JLabel();
        excludeSuffixTextField = new JTextField();
        JButton excludeSuffixSaveButton = new JButton();

        setLayout(new GridBagLayout());
        ((GridBagLayout)getLayout()).columnWidths = new int[] {0, 0};
        ((GridBagLayout)getLayout()).rowHeights = new int[] {0, 0};
        ((GridBagLayout)getLayout()).columnWeights = new double[] {1.0, 1.0E-4};
        ((GridBagLayout)getLayout()).rowWeights = new double[] {1.0, 1.0E-4};

        {
            mainTabbedPane.addTab("Rules", ruleTabbedPane);

            {
                rulePanel.setLayout(new GridBagLayout());
                ((GridBagLayout) rulePanel.getLayout()).columnWidths = new int[] {0, 0, 0, 0, 0};
                ((GridBagLayout) rulePanel.getLayout()).rowHeights = new int[] {0, 0, 0};
                ((GridBagLayout) rulePanel.getLayout()).columnWeights = new double[] {0.0, 1.0, 0.0, 0.0, 1.0E-4};
                ((GridBagLayout) rulePanel.getLayout()).rowWeights = new double[] {0.0, 0.0, 1.0E-4};

                rulesPathTextField.setEditable(false);
                rulePanel.add(rulesPathTextField, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0,
                        GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                        new Insets(5, 0, 5, 5), 0, 0));

                rulesPathLabel.setText("Rules Path:");
                rulePanel.add(rulesPathLabel, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                        GridBagConstraints.WEST, GridBagConstraints.VERTICAL,
                        new Insets(5, 5, 5, 5), 0, 0));

                onlineUpdateButton.setText("Online Update");
                onlineUpdateButton.addActionListener(this::onlineUpdateActionPerformed);
                rulePanel.add(onlineUpdateButton, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0,
                        GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                        new Insets(5, 0, 5, 5), 0, 0));

                reloadButton.setText("Reload");
                reloadButton.addActionListener(this::reloadActionPerformed);
                rulePanel.add(reloadButton, new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0,

                        GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                        new Insets(5, 0, 5, 5), 0, 0));

                excludeSuffixLabel.setText("Exclude Suffix:");
                rulePanel.add(excludeSuffixLabel, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0,
                        GridBagConstraints.SOUTHWEST, GridBagConstraints.NONE,
                        new Insets(0, 5, 5, 5), 0, 0));
                rulePanel.add(excludeSuffixTextField, new GridBagConstraints(1, 1, 1, 1, 0.0, 0.0,
                        GridBagConstraints.SOUTH, GridBagConstraints.HORIZONTAL,
                        new Insets(0, 0, 0, 5), 0, 0));

                excludeSuffixSaveButton.setText("Save");
                excludeSuffixSaveButton.addActionListener(this::excludeSuffixSaveActionPerformed);
                rulePanel.add(excludeSuffixSaveButton, new GridBagConstraints(2, 1, 1, 1, 0.0, 0.0,
                        GridBagConstraints.SOUTH, GridBagConstraints.HORIZONTAL,
                        new Insets(0, 0, 0, 5), 0, 0));
            }
            mainTabbedPane.addTab("Config", rulePanel);
            mainTabbedPane.addTab("Databoard", this.databoardPanel);
        }
        add(mainTabbedPane, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 0, 0, 0), 0, 0));

        ConfigEntry.globalRules.keySet().forEach(i-> ruleTabbedPane.addTab(i, new RulePane(
                ConfigEntry.globalRules.get(i),
                ruleTabbedPane)));

        ruleTabbedPane.addTab("...",new JLabel());

        rulesPathTextField.setText(ConfigLoader.getRulesFilePath());
        excludeSuffixTextField.setText(loadConn.getExcludeSuffix());
        ruleSwitch = new TabTitleEditListener(ruleTabbedPane);
        ruleTabbedPane.addChangeListener(ruleSwitch);
        ruleTabbedPane.addMouseListener(ruleSwitch);
        deleteMenuItem.addActionListener(this::closeTabActionPerformed);
        tabMenu.add(deleteMenuItem);
    }

    private JTabbedPane ruleTabbedPane;
    private JTextField rulesPathTextField;
    private JTextField excludeSuffixTextField;
    private Databoard databoardPanel;
    protected static JPopupMenu tabMenu = new JPopupMenu();
    private final JMenuItem deleteMenuItem = new JMenuItem("Delete");
    private TabTitleEditListener ruleSwitch;
}

class TabTitleEditListener extends MouseAdapter implements ChangeListener, DocumentListener {
    protected final JTextField ruleEditTextField = new JTextField();
    protected final JTabbedPane ruleEditTabbedPane;
    protected int editingIndex = -1;
    protected int len = -1;
    protected Boolean listen = true;
    protected Dimension dim;
    protected Component tabComponent;
    protected Boolean isRenameOk = false;
    protected RuleProcessor ruleProcessor = new RuleProcessor();

    protected final Action startEditing = new AbstractAction() {
        @Override public void actionPerformed(ActionEvent e) {
            editingIndex = ruleEditTabbedPane.getSelectedIndex();
            tabComponent = ruleEditTabbedPane.getTabComponentAt(editingIndex);
            ruleEditTabbedPane.setTabComponentAt(editingIndex, ruleEditTextField);
            isRenameOk = true;
            ruleEditTextField.setVisible(true);
            ruleEditTextField.setText(ruleEditTabbedPane.getTitleAt(editingIndex));
            ruleEditTextField.selectAll();
            ruleEditTextField.requestFocusInWindow();
            len = ruleEditTextField.getText().length();
            dim = ruleEditTextField.getPreferredSize();
            ruleEditTextField.setMinimumSize(dim);
        }
    };

    protected final Action renameTabTitle = new AbstractAction() {
        @Override public void actionPerformed(ActionEvent e) {
            String title = ruleEditTextField.getText().trim();
            if (editingIndex >= 0 && !title.isEmpty()) {
                String oldName = ruleEditTabbedPane.getTitleAt(editingIndex);
                ruleEditTabbedPane.setTitleAt(editingIndex, title);
                ruleProcessor.renameRuleGroup(oldName,title);
            }
            cancelEditing.actionPerformed(null);
        }
    };

    protected final Action cancelEditing = new AbstractAction() {
        @Override public void actionPerformed(ActionEvent e) {
            if (editingIndex >= 0) {
                ruleEditTabbedPane.setTabComponentAt(editingIndex, tabComponent);
                ruleEditTextField.setVisible(false);
                editingIndex = -1;
                len = -1;
                tabComponent = null;
                ruleEditTextField.setPreferredSize(null);
                ruleEditTabbedPane.requestFocusInWindow();
            }
        }
    };

    protected TabTitleEditListener(JTabbedPane tabbedPane) {
        super();
        this.ruleEditTabbedPane = tabbedPane;
        ruleEditTextField.setBorder(BorderFactory.createEmptyBorder());
        ruleEditTextField.addFocusListener(new FocusAdapter() {
            @Override public void focusLost(FocusEvent e) {
                renameTabTitle.actionPerformed(null);
            }
        });
        InputMap im = ruleEditTextField.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = ruleEditTextField.getActionMap();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancel-editing");
        am.put("cancel-editing", cancelEditing);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "rename-tab-title");
        am.put("rename-tab-title", renameTabTitle);
        ruleEditTextField.getDocument().addDocumentListener(this);
        tabbedPane.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "start-editing");
        tabbedPane.getActionMap().put("start-editing", startEditing);
    }

    @Override public void stateChanged(ChangeEvent e) {
        if (e.getSource() instanceof JTabbedPane && listen) {
            JTabbedPane pane = (JTabbedPane) e.getSource();
            if (!isRenameOk){
                if (pane.getSelectedIndex() == pane.getComponentCount()-1){
                    newTab();
                }
            }else{
                if (pane.getSelectedIndex() == pane.getComponentCount()-2){
                    newTab();
                }
            }
        }
        renameTabTitle.actionPerformed(null);
    }

    public void newTab(){
        Object[][] data = new Object[][]{{false, "New Name", "(New Regex)", "gray", "any", "nfa", false}};
        insertTab(ruleEditTabbedPane, ruleProcessor.newRule(),data);
    }

    public void insertTab(JTabbedPane pane,String title,Object[][] data){
        pane.addTab(title,new RulePane(data,pane));
        pane.remove(pane.getSelectedIndex());
        pane.addTab("...",new JLabel());
    }

    public void setListen(Boolean listen){
        this.listen = listen;
    }

    @Override public void insertUpdate(DocumentEvent e) {
        updateTabSize();
    }

    @Override public void removeUpdate(DocumentEvent e) {
        updateTabSize();
    }

    @Override public void changedUpdate(DocumentEvent e) {}

    @Override public void mouseClicked(MouseEvent e) {
        switch (e.getButton()){
            case 1:
            {
                Rectangle r = ruleEditTabbedPane.getBoundsAt(ruleEditTabbedPane.getSelectedIndex());
                boolean isDoubleClick = e.getClickCount() >= 2;
                if (isDoubleClick && r.contains(e.getPoint())) {
                    startEditing.actionPerformed(null);
                } else {
                    renameTabTitle.actionPerformed(null);
                }
                break;
            }
            case 3:{
                MainUI.tabMenu.show(e.getComponent(),e.getX(),e.getY());
                break;
            }
            default:
                break;
        }
    }

    protected void updateTabSize() {
        ruleEditTextField.setPreferredSize(ruleEditTextField.getText().length() > len ? null : dim);
        ruleEditTabbedPane.revalidate();
    }
}