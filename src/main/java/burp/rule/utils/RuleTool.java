package burp.rule.utils;

import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import java.io.FileOutputStream;
import javax.swing.JOptionPane;

/**
 * @author EvilChen
 */
public class RuleTool {
    private String rulesFilePath;

    public RuleTool(String rulesFilePath) {
        this.rulesFilePath = rulesFilePath;
    }

    public void getRulesFromSite() {
        String url = "https://cdn.jsdelivr.net/gh/gh0stkey/HaE@gh-pages/Rules.yml";
        OkHttpClient httpClient = new OkHttpClient();
        Request httpRequest = new Request.Builder().url(url).get().build();
        try {
            Response httpResponse = httpClient.newCall(httpRequest).execute();
            // 获取官方规则文件，在线更新写入
            FileOutputStream fileOutputStream = new FileOutputStream(this.rulesFilePath);
            fileOutputStream.write(httpResponse.body().bytes());
            JOptionPane.showMessageDialog(null, "Config file updated successfully!", "Error",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ignored) {
            JOptionPane.showMessageDialog(null, "Please check your network!", "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}
