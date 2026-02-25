package hae.component;

import burp.api.montoya.MontoyaApi;
import hae.component.board.Databoard;
import hae.component.board.message.MessageTableModel;
import hae.component.rule.Rules;
import hae.repository.DataRepository;
import hae.repository.RuleRepository;
import hae.service.HandlerRegistry;
import hae.service.ValidatorService;
import hae.utils.ConfigLoader;
import hae.utils.UIEnhancer;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;

public class Main extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final MessageTableModel messageTableModel;
    private final RuleRepository ruleRepository;
    private final DataRepository dataRepository;
    private final HandlerRegistry handlerRegistry;
    private final ValidatorService validatorService;

    public Main(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel,
                RuleRepository ruleRepository, DataRepository dataRepository, HandlerRegistry handlerRegistry,
                ValidatorService validatorService) {
        this.api = api;
        this.configLoader = configLoader;
        this.messageTableModel = messageTableModel;
        this.ruleRepository = ruleRepository;
        this.dataRepository = dataRepository;
        this.handlerRegistry = handlerRegistry;
        this.validatorService = validatorService;

        initComponents();
    }

    private void initComponents() {
        setLayout(new GridBagLayout());
        ((GridBagLayout) getLayout()).columnWidths = new int[]{0, 0};
        ((GridBagLayout) getLayout()).rowHeights = new int[]{0, 0};
        ((GridBagLayout) getLayout()).columnWeights = new double[]{1.0, 1.0E-4};
        ((GridBagLayout) getLayout()).rowWeights = new double[]{1.0, 1.0E-4};

        JTabbedPane mainTabbedPane = new JTabbedPane();

        // 新增Logo
        JTabbedPane haeTabbedPane = new JTabbedPane();
        boolean isDarkBg = UIEnhancer.isDarkColor(haeTabbedPane.getBackground());
        haeTabbedPane.addTab("", getImageIcon(isDarkBg), mainTabbedPane);
        // 中文Slogan：赋能白帽，高效作战
        haeTabbedPane.addTab(" Highlighter and Extractor - Empower ethical hacker for efficient operations. ", null);
        haeTabbedPane.setEnabledAt(1, false);
        haeTabbedPane.addPropertyChangeListener("background", new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent e) {
                boolean isDarkBg = UIEnhancer.isDarkColor(haeTabbedPane.getBackground());
                haeTabbedPane.setIconAt(0, getImageIcon(isDarkBg));
            }
        });

        add(haeTabbedPane, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 0, 0, 0), 0, 0));

        // 依次添加Rules、Config、Databoard
        Rules rules = new Rules(api, configLoader, ruleRepository);
        mainTabbedPane.addTab("Rules", rules);
        mainTabbedPane.addTab("Databoard", new Databoard(api, configLoader, messageTableModel, dataRepository, validatorService));
        mainTabbedPane.addTab("Config", new Config(api, configLoader, messageTableModel, rules, handlerRegistry));
    }

    private ImageIcon getImageIcon(boolean isDark) {
        ClassLoader classLoader = getClass().getClassLoader();
        URL imageURL;
        if (isDark) {
            imageURL = classLoader.getResource("logo/logo.png");
        } else {
            imageURL = classLoader.getResource("logo/logo_black.png");
        }
        ImageIcon originalIcon = new ImageIcon(imageURL);
        Image originalImage = originalIcon.getImage();
        Image scaledImage = originalImage.getScaledInstance(30, 20, Image.SCALE_FAST);
        return new ImageIcon(scaledImage);
    }
}
