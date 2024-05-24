package hae.utils.project;

import burp.api.montoya.MontoyaApi;
import hae.utils.project.model.HaeFileContent;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class ProjectProcessor {
    private final MontoyaApi api;

    public ProjectProcessor(MontoyaApi api) {
        this.api = api;
    }

    public boolean createHaeFile(String haeFilePath, String host, Map<String, List<String>> dataMap, Map<String, Map<String, String>> httpMap) {
        ByteArrayOutputStream dataYamlStream = new ByteArrayOutputStream();
        ByteArrayOutputStream httpYamlStream = new ByteArrayOutputStream();
        Yaml yaml = new Yaml();

        yaml.dump(dataMap, new OutputStreamWriter(dataYamlStream, StandardCharsets.UTF_8));
        yaml.dump(httpMap, new OutputStreamWriter(httpYamlStream, StandardCharsets.UTF_8));

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(haeFilePath))) {
            zipOut.putNextEntry(new ZipEntry("info.txt"));
            zipOut.write(host.getBytes(StandardCharsets.UTF_8));
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("data.yml"));
            zipOut.write(dataYamlStream.toByteArray());
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("http.yml"));
            zipOut.write(httpYamlStream.toByteArray());
            zipOut.closeEntry();
        } catch (Exception e) {
            api.logging().logToOutput(e.getMessage());
            return false;
        }

        return true;
    }

    public HaeFileContent readHaeFile(String haeFilePath) {
        HaeFileContent haeFileContent = new HaeFileContent(api);
        Yaml yaml = new Yaml();

        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(haeFilePath))) {
            ZipEntry entry;
            while ((entry = zipIn.getNextEntry()) != null) {
                switch (entry.getName()) {
                    case "info.txt":
                        haeFileContent.setHost(new String(zipIn.readAllBytes(), StandardCharsets.UTF_8));
                        break;
                    case "data.yml":
                        haeFileContent.setDataMap(yaml.load(new InputStreamReader(zipIn, StandardCharsets.UTF_8)));
                        break;
                    case "http.yml":
                        haeFileContent.setHttpMap(yaml.load(new InputStreamReader(zipIn, StandardCharsets.UTF_8)));
                        break;
                }
                zipIn.closeEntry();
            }
        } catch (Exception e) {
            api.logging().logToOutput(e.getMessage());
            return null;
        }
        return haeFileContent;
    }
}

