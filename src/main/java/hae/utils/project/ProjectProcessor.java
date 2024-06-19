package hae.utils.project;

import burp.api.montoya.MontoyaApi;
import hae.utils.project.model.HaeFileContent;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class ProjectProcessor {
    private final MontoyaApi api;

    public ProjectProcessor(MontoyaApi api) {
        this.api = api;
    }

    public boolean createHaeFile(String haeFilePath, String host, Map<String, List<String>> dataMap, Map<String, Map<String, Object>> urlMap, Map<String, Map<String, Object>> httpMap) {
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);

        List<Callable<Void>> tasks = new ArrayList<>();

        ByteArrayOutputStream dataYamlStream = new ByteArrayOutputStream();
        ByteArrayOutputStream urlYamlStream = new ByteArrayOutputStream();
        Yaml yaml = new Yaml();

        yaml.dump(dataMap, new OutputStreamWriter(dataYamlStream, StandardCharsets.UTF_8));
        yaml.dump(urlMap, new OutputStreamWriter(urlYamlStream, StandardCharsets.UTF_8));

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(haeFilePath))) {
            zipOut.putNextEntry(new ZipEntry("info"));
            zipOut.write(host.getBytes(StandardCharsets.UTF_8));
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("data"));
            zipOut.write(dataYamlStream.toByteArray());
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("url"));
            zipOut.write(urlYamlStream.toByteArray());
            zipOut.closeEntry();

            for (String httpHash : httpMap.keySet()) {
                Map<String, Object> httpItem = httpMap.get(httpHash);
                tasks.add(() -> {
                    try {
                        ByteArrayOutputStream httpOutStream = new ByteArrayOutputStream();
                        byte[] request = (byte[]) httpItem.get("request");
                        byte[] response = (byte[]) httpItem.get("response");

                        httpOutStream.write(response);
                        httpOutStream.write(request);

                        synchronized (zipOut) {
                            zipOut.putNextEntry(new ZipEntry(String.format("http/%s", httpHash)));
                            zipOut.write(httpOutStream.toByteArray());
                            zipOut.closeEntry();
                        }
                    } catch (Exception e) {
                        api.logging().logToError("createHaeFile: " + e.getMessage());
                    }

                    return null;
                });
            }

            executor.invokeAll(tasks);
        } catch (Exception e) {
            api.logging().logToError("createHaeFile: " + e.getMessage());
            return false;
        } finally {
            executor.shutdown();
        }

        return true;
    }

    public HaeFileContent readHaeFile(String haeFilePath) {
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
        List<Callable<Void>> tasks = new ArrayList<>();

        HaeFileContent haeFileContent = new HaeFileContent(api);
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setMaxAliasesForCollections(Integer.MAX_VALUE);
        loaderOptions.setCodePointLimit(Integer.MAX_VALUE);
        Yaml yaml = new Yaml(loaderOptions);
        Path tempDirectory = null;

        try {
            if (hasValidStructure(haeFilePath)) {
                tempDirectory = Files.createTempDirectory("hae");
                haeFileContent.setHttpPath(tempDirectory.toString());

                try (ZipFile zipFile = new ZipFile(haeFilePath)) {
                    Enumeration<? extends ZipEntry> entries = zipFile.entries();
                    while (entries.hasMoreElements()) {
                        ZipEntry entry = entries.nextElement();
                        String fileName = entry.getName();
                        if (fileName.startsWith("http/")) {
                            Path filePath = tempDirectory.resolve(fileName.substring("http/".length()));

                            tasks.add(() -> {
                                try (InputStream in = zipFile.getInputStream(entry)) {
                                    Files.copy(in, filePath, StandardCopyOption.REPLACE_EXISTING);
                                } catch (IOException e) {
                                    api.logging().logToError("readHaeFile: " + e.getMessage());
                                }

                                return null;
                            });
                        } else {
                            try (InputStream in = zipFile.getInputStream(entry)) {
                                switch (fileName) {
                                    case "info" ->
                                            haeFileContent.setHost(new String(in.readAllBytes(), StandardCharsets.UTF_8));
                                    case "data" ->
                                            haeFileContent.setDataMap(yaml.load(new InputStreamReader(in, StandardCharsets.UTF_8)));
                                    case "url" ->
                                            haeFileContent.setUrlMap(yaml.load(new InputStreamReader(in, StandardCharsets.UTF_8)));
                                }
                            }
                        }
                    }

                    executor.invokeAll(tasks);
                }
            }
        } catch (Exception e) {
            api.logging().logToError("readHaeFile: " + e.getMessage());
            if (tempDirectory != null) {
                FileProcessor.deleteDirectoryWithContents(tempDirectory);
            }
            haeFileContent = null;
        } finally {
            executor.shutdown();
        }

        return haeFileContent;
    }

    private boolean hasValidStructure(String zipFilePath) {
        Set<String> requiredRootEntries = new HashSet<>();
        requiredRootEntries.add("info");
        requiredRootEntries.add("data");
        requiredRootEntries.add("url");

        boolean hasHttpDirectoryWithFiles = false;

        try {
            ZipFile zipFile = new ZipFile(zipFilePath);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();

            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                if (!entry.isDirectory() && !name.contains("/")) {
                    requiredRootEntries.remove(name);
                }

                if (name.startsWith("http/") && !entry.isDirectory()) {
                    hasHttpDirectoryWithFiles = true;
                }

                if (requiredRootEntries.isEmpty() && hasHttpDirectoryWithFiles) {
                    break;
                }
            }

            zipFile.close();
        } catch (Exception ignored) {
        }

        return requiredRootEntries.isEmpty() && hasHttpDirectoryWithFiles;
    }
}

