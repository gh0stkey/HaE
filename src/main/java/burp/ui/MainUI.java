package burp.ui;

import org.jetbrains.annotations.NotNull;
import burp.yaml.LoadConfigFile;
import burp.yaml.LoadRule;
import burp.yaml.SetRuleConfig;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.util.Map;

/*
 * @author LinChen
 */

public class MainUI extends JPanel{
    public MainUI() {
        initComponents();
    }
    public void closeTabActionPerformed(ActionEvent e){
        if (tabbedPane1.getTabCount()>2){
            if (tabbedPane1.getSelectedIndex()!=0){
                SetRuleConfig setruleconfig = new SetRuleConfig();
                setruleconfig.deleteRules(tabbedPane1.getTitleAt(tabbedPane1.getSelectedIndex()));
                tabbedPane1.remove(tabbedPane1.getSelectedIndex());
                tabbedPane1.setSelectedIndex(tabbedPane1.getSelectedIndex()-1);
            }else{
                SetRuleConfig setruleconfig = new SetRuleConfig();
                setruleconfig.deleteRules(tabbedPane1.getTitleAt(tabbedPane1.getSelectedIndex()));
                tabbedPane1.remove(tabbedPane1.getSelectedIndex());
                tabbedPane1.setSelectedIndex(tabbedPane1.getSelectedIndex());
            }
        }
    }

    private void SelectFileMouseClicked(MouseEvent e) {
        JFileChooser chooseconfig = new JFileChooser();
        chooseconfig.setFileSelectionMode(JFileChooser.FILES_ONLY);
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Yaml File (.yml/.yaml)","yaml", "yml");
        chooseconfig.setFileFilter(filter);
        int selectframe = chooseconfig.showDialog(new JLabel(),"Select");
        if (selectframe == JFileChooser.APPROVE_OPTION){
            String configpath = chooseconfig.getSelectedFile().toString();
            reloadRule(configpath);
            loadfile.setConfigPath(configpath);
        }
        configfilepathtext.setText(loadfile.getConfigPath());
    }
    private void reloadRule(String configfile){
        tabbedPane1.removeAll();
        LoadRule loadrule = new LoadRule(configfile);
        Map<String,Object[][]> config = loadrule.getConfig();
        ruleSwitch.setListen(false);
        config.keySet().forEach(i->tabbedPane1.addTab(i,new RulePane(config.get(i),tabbedPane1)));
        tabbedPane1.addTab("...",new JLabel());
        ruleSwitch.setListen(true);
    }
    private void reloadRule(){
        tabbedPane1.removeAll();
        LoadRule loadrule = new LoadRule(loadfile.getConfigPath());
        Map<String,Object[][]> config = loadrule.getConfig();
        ruleSwitch.setListen(false);
        config.keySet().forEach(i->tabbedPane1.addTab(i,new RulePane(config.get(i),tabbedPane1))
        );
        tabbedPane1.addTab("...",new JLabel());
        ruleSwitch.setListen(true);
    }

    private void reloadMouseClicked(MouseEvent e) {
        reloadRule();
    }
    private void ESSaveMouseClicked(MouseEvent e) {
        // TODO add your code here
        LoadConfigFile lcf = new LoadConfigFile();
        lcf.setExcludeSuffix(EStext.getText());
    }
    private void initComponents() {
        tabbedPane2 = new JTabbedPane();
        tabbedPane1 = new JTabbedPane();
        panel3 = new JPanel();
        configfilepathtext = new JTextField();
        label1 = new JLabel();
        SelectFile = new JButton();
        reload = new JButton();
        label2 = new JLabel();
        EStext = new JTextField();
        ESSave = new JButton();

        //======== this ========
        setLayout(new GridBagLayout());
        ((GridBagLayout)getLayout()).columnWidths = new int[] {0, 0};
        ((GridBagLayout)getLayout()).rowHeights = new int[] {0, 0};
        ((GridBagLayout)getLayout()).columnWeights = new double[] {1.0, 1.0E-4};
        ((GridBagLayout)getLayout()).rowWeights = new double[] {1.0, 1.0E-4};

        //======== tabbedPane2 ========
        {
            tabbedPane2.addTab("Rules", tabbedPane1);

            //======== panel3 ========
            {
                panel3.setLayout(new GridBagLayout());
                ((GridBagLayout)panel3.getLayout()).columnWidths = new int[] {0, 0, 0, 0, 0};
                ((GridBagLayout)panel3.getLayout()).rowHeights = new int[] {0, 0, 0};
                ((GridBagLayout)panel3.getLayout()).columnWeights = new double[] {0.0, 1.0, 0.0, 0.0, 1.0E-4};
                ((GridBagLayout)panel3.getLayout()).rowWeights = new double[] {0.0, 0.0, 1.0E-4};

                //---- configfilepathtext ----
                configfilepathtext.setEditable(false);
                panel3.add(configfilepathtext, new GridBagConstraints(1, 0, 1, 1, 0.0, 0.0,
                        GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                        new Insets(5, 0, 5, 5), 0, 0));

                //---- label1 ----
                label1.setText("Config File Path:");
                panel3.add(label1, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                        GridBagConstraints.WEST, GridBagConstraints.VERTICAL,
                        new Insets(5, 5, 5, 5), 0, 0));

                //---- SelectFile ----
                SelectFile.setText("Select File ...");
                SelectFile.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        SelectFileMouseClicked(e);
                    }
                });
                panel3.add(SelectFile, new GridBagConstraints(2, 0, 1, 1, 0.0, 0.0,
                        GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                        new Insets(5, 0, 5, 5), 0, 0));

                //---- reload ----
                reload.setText("Reload");
                reload.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        reloadMouseClicked(e);
                    }
                });
                panel3.add(reload, new GridBagConstraints(3, 0, 1, 1, 0.0, 0.0,

                        GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                        new Insets(5, 0, 5, 5), 0, 0));
//---- label2 ----
                label2.setText("ExcludeSuffix:");
                panel3.add(label2, new GridBagConstraints(0, 1, 1, 1, 0.0, 0.0,
                        GridBagConstraints.SOUTHWEST, GridBagConstraints.NONE,
                        new Insets(0, 5, 5, 5), 0, 0));
                panel3.add(EStext, new GridBagConstraints(1, 1, 1, 1, 0.0, 0.0,
                        GridBagConstraints.SOUTH, GridBagConstraints.HORIZONTAL,
                        new Insets(0, 0, 0, 5), 0, 0));

                //---- ESSave ----
                ESSave.setText("Save");
                ESSave.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        ESSaveMouseClicked(e);
                    }
                });
                panel3.add(ESSave, new GridBagConstraints(2, 1, 1, 1, 0.0, 0.0,
                        GridBagConstraints.SOUTH, GridBagConstraints.HORIZONTAL,
                        new Insets(0, 0, 0, 5), 0, 0));
            }
            tabbedPane2.addTab("Config", panel3);
        }
        add(tabbedPane2, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 0, 0, 0), 0, 0));
        // JFormDesigner - End of component initialization  //GEN-END:initComponents

        LoadRule loadRule = new LoadRule(loadfile.getConfigPath());
        Map<String,Object[][]> config = loadRule.getConfig();
        config.keySet().forEach(i->tabbedPane1.addTab(i,new RulePane(config.get(i),tabbedPane1)));

        tabbedPane1.addTab("...",new JLabel());

        //TabTitleEditListener ruleSwitch = new TabTitleEditListener(tabbedPane1);
        configfilepathtext.setText(loadfile.getConfigPath());
        LoadConfigFile lcf =new LoadConfigFile();
        EStext.setText(lcf.getExcludeSuffix());
        ruleSwitch = new TabTitleEditListener(tabbedPane1);
        tabbedPane1.addChangeListener(ruleSwitch);
        tabbedPane1.addMouseListener(ruleSwitch);
        closeTab.addActionListener(e -> closeTabActionPerformed(e));
        tabMenu.add(closeTab);
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables
    private JTabbedPane tabbedPane2;
    private JTabbedPane tabbedPane1;
    private JPanel panel3;
    private JTextField configfilepathtext;
    private JLabel label1;
    private JButton SelectFile;
    private JButton reload;
    private JLabel label2;
    private JTextField EStext;
    private JButton ESSave;
    // JFormDesigner - End of variables declaration  //GEN-END:variables
    protected static JPopupMenu tabMenu = new JPopupMenu();
    private JMenuItem closeTab = new JMenuItem("Delete");
    private TabTitleEditListener ruleSwitch;
    private LoadConfigFile loadfile = new LoadConfigFile();
}

class TabTitleEditListener extends MouseAdapter implements ChangeListener, DocumentListener {
    protected final JTextField editor = new JTextField();
    protected final JTabbedPane tabbedPane;
    protected int editingIdx = -1;
    protected int len = -1;
    protected Boolean listen = true;
    protected Dimension dim;
    protected Component tabComponent;
    protected Boolean isRenamesucc = false;
    protected LoadConfigFile loadfile = new LoadConfigFile();
    protected LoadRule lr = new LoadRule(loadfile.getConfigPath());
    protected SetRuleConfig setRuleConfig = new SetRuleConfig();
    protected final Action startEditing = new AbstractAction() {
        @Override public void actionPerformed(ActionEvent e) {
            editingIdx = tabbedPane.getSelectedIndex();
            tabComponent = tabbedPane.getTabComponentAt(editingIdx);
            tabbedPane.setTabComponentAt(editingIdx, editor);
            isRenamesucc = true;
            editor.setVisible(true);
            editor.setText(tabbedPane.getTitleAt(editingIdx));
            editor.selectAll();
            editor.requestFocusInWindow();
            len = editor.getText().length();
            dim = editor.getPreferredSize();
            editor.setMinimumSize(dim);
        }
    };
    protected final Action renameTabTitle = new AbstractAction() {
        @Override public void actionPerformed(ActionEvent e) {
            String title = editor.getText().trim();
            if (editingIdx >= 0 && !title.isEmpty()) {
                String oldname = tabbedPane.getTitleAt(editingIdx);
                tabbedPane.setTitleAt(editingIdx, title);
                setRuleConfig.rename(oldname,title);
            }
            cancelEditing.actionPerformed(null);
        }
    };
    protected final Action cancelEditing = new AbstractAction() {
        @Override public void actionPerformed(ActionEvent e) {
            if (editingIdx >= 0) {
                tabbedPane.setTabComponentAt(editingIdx, tabComponent);
                editor.setVisible(false);
                editingIdx = -1;
                len = -1;
                tabComponent = null;
                editor.setPreferredSize(null);
                tabbedPane.requestFocusInWindow();
            }
        }
    };

    protected TabTitleEditListener(JTabbedPane tabbedPane) {
        super();
        this.tabbedPane = tabbedPane;
        editor.setBorder(BorderFactory.createEmptyBorder());
        editor.addFocusListener(new FocusAdapter() {
            @Override public void focusLost(FocusEvent e) {
                renameTabTitle.actionPerformed(null);
            }
        });
        InputMap im = editor.getInputMap(JComponent.WHEN_FOCUSED);
        ActionMap am = editor.getActionMap();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancel-editing");
        am.put("cancel-editing", cancelEditing);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "rename-tab-title");
        am.put("rename-tab-title", renameTabTitle);
        editor.getDocument().addDocumentListener(this);
        tabbedPane.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "start-editing");
        tabbedPane.getActionMap().put("start-editing", startEditing);
            }
            @Override public void stateChanged(ChangeEvent e) {
                if (e.getSource() instanceof JTabbedPane && listen) {
                    JTabbedPane pane = (JTabbedPane) e.getSource();
                    if (!isRenamesucc){
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
        Object[][] data = new Object[][]{{false, "New Name", "(New Regex)", "gray", "any", "nfa"}};
        insertTab(tabbedPane,setRuleConfig.newRules(),data);
    }
    public void insertTab(@NotNull JTabbedPane pane,String title,Object[][] data){
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
                Rectangle r = tabbedPane.getBoundsAt(tabbedPane.getSelectedIndex());
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
        editor.setPreferredSize(editor.getText().length() > len ? null : dim);
        tabbedPane.revalidate();
    }
}