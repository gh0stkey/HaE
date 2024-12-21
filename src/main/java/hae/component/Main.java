package hae.component;

import burp.api.montoya.MontoyaApi;
import hae.component.board.Databoard;
import hae.component.board.message.MessageTableModel;
import hae.component.rule.Rules;
import hae.utils.ConfigLoader;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.URL;

public class Main extends JPanel {
    private final MontoyaApi api;
    private final ConfigLoader configLoader;
    private final MessageTableModel messageTableModel;

    public Main(MontoyaApi api, ConfigLoader configLoader, MessageTableModel messageTableModel) {
        this.api = api;
        this.configLoader = configLoader;
        this.messageTableModel = messageTableModel;

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
        JTabbedPane HaETabbedPane = new JTabbedPane();
        boolean isDarkBg = isDarkBg(HaETabbedPane);
        HaETabbedPane.addTab("", getImageIcon(isDarkBg), mainTabbedPane);
        // 中文Slogan：赋能白帽，高效作战
        HaETabbedPane.addTab(" Highlighter and Extractor - Empower ethical hacker for efficient operations. ", null);
        HaETabbedPane.setEnabledAt(1, false);
        HaETabbedPane.addPropertyChangeListener("background", new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent e) {
                boolean isDarkBg = isDarkBg(HaETabbedPane);
                HaETabbedPane.setIconAt(0, getImageIcon(isDarkBg));
            }
        });

        add(HaETabbedPane, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                new Insets(0, 0, 0, 0), 0, 0));

        // 依次添加Rules、Config、Databoard
        Rules rules = new Rules(api, configLoader);
        mainTabbedPane.addTab("Rules", rules);
        mainTabbedPane.addTab("Databoard", new Databoard(api, configLoader, messageTableModel));
        mainTabbedPane.addTab("Config", new Config(api, configLoader, messageTableModel, rules));
    }

    private boolean isDarkBg(JTabbedPane HaETabbedPane) {
        Color bg = HaETabbedPane.getBackground();
        int r = bg.getRed();
        int g = bg.getGreen();
        int b = bg.getBlue();
        int avg = (r + g + b) / 3;

        return avg < 128;
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
