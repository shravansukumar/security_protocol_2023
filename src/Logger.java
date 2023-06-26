import java.io.FileWriter;
import java.io.IOException;

public class Logger {

    private static Logger instance = null;

    private static final String FILE_PATH = "Logger.txt";

    public void saveLog(String content) {
        try (FileWriter fileWriter = new FileWriter(FILE_PATH, true)) {
            fileWriter.write(content);
            fileWriter.write(System.lineSeparator()); // Add a new line after the content
            System.out.println("String saved to file successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static Logger getInstance() {
        if (instance == null) {
            instance = new Logger();
        }
        return instance;
    }

}