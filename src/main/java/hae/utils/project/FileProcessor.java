package hae.utils.project;

import java.io.File;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;

public class FileProcessor {
    public static void deleteDirectoryWithContents(Path pathToBeDeleted) {
        if (pathToBeDeleted != null) {
            try {
                Files.walk(pathToBeDeleted)
                        .sorted(Comparator.reverseOrder())
                        .map(Path::toFile)
                        .forEach(File::delete);
            } catch (Exception ignored) {
            }
        }
    }

    public static byte[] readFileContent(String basePath, String fileName) {
        Path filePath = Paths.get(basePath, fileName);
        Path path = Paths.get(basePath);
        try {
            byte[] fileContent = Files.readAllBytes(filePath);

            Files.deleteIfExists(filePath);

            boolean isEmpty = isDirectoryEmpty(path);
            if (isEmpty) {
                Files.deleteIfExists(path);
            }

            return fileContent;
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private static boolean isDirectoryEmpty(Path directory) throws Exception {
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(directory)) {
            return !dirStream.iterator().hasNext();
        }
    }
}
