package burp.rule.utils;

import burp.*;
import burp.config.ConfigEntry;
import burp.config.ConfigLoader;
import java.io.FileOutputStream;
import java.net.URL;
import java.util.Arrays;
import javax.swing.JOptionPane;

/**
 * @author EvilChen
 */
public class RuleTool {
    private String rulesFilePath;
    private boolean isSuccess;

    public RuleTool(String rulesFilePath) {
        this.rulesFilePath = rulesFilePath;
    }

    public void getRulesFromSite() {
        // 以独立线程使用BurpSuite官方请求接口获取规则
        Thread t = new Thread(()->{
            try {
                URL url = new URL("https://cdn.jsdelivr.net/gh/gh0stkey/HaE@gh-pages/Rules.yml");
                IHttpService iHttpService = BurpExtender.helpers.buildHttpService(url.getHost(), 443, true);
                IHttpRequestResponse iHttpRequestResponse = BurpExtender.callbacks.makeHttpRequest(iHttpService, BurpExtender.helpers.buildHttpRequest(url));
                byte[] responseByte = iHttpRequestResponse.getResponse();
                IResponseInfo iResponseInfo = BurpExtender.helpers.analyzeResponse(responseByte);
                int bodyOffset = iResponseInfo.getBodyOffset();
                byte[] responseBodyByte = Arrays.copyOfRange(responseByte, bodyOffset, responseByte.length);
                FileOutputStream fileOutputStream = new FileOutputStream(this.rulesFilePath);
                fileOutputStream.write(responseBodyByte);
                fileOutputStream.close();
                isSuccess = true;
            } catch (Exception e) {
                isSuccess = false;
            }
        });
        t.start();
        try {
            t.join(10000);
        } catch (Exception e) {
            isSuccess = false;
        }

        if (isSuccess) {
            JOptionPane.showMessageDialog(null, "Rules update successfully!", "Info", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(null, "Rule update failed, please check the network!", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
