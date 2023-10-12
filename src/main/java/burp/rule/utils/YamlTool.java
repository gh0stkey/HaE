package burp.rule.utils;

import java.util.Map;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import org.yaml.snakeyaml.representer.Representer;

/**
 * @author EvilChen
 */

public class YamlTool {

    public static Yaml newStandardYaml() {
        DumperOptions dop = new DumperOptions();
        dop.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        Representer representer = new Representer();
        return new Yaml(representer, dop);
    }

    public static Map<String, Object> loadYaml(String filePath) {
        try {
            InputStream inputStream = new FileInputStream(filePath);
            Yaml yaml = newStandardYaml();
            return yaml.load(inputStream);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}

