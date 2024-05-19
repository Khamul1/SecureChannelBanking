import javax.swing.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class SecureChatApplication {
    private ChatClient chatClient1;
    private ChatClient chatClient2;
    private ActivityMonitor activityMonitor;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            SecureChatApplication app = new SecureChatApplication();
            app.initApp();
        });
    }

    private void initApp() {
        activityMonitor = new ActivityMonitor();
        activityMonitor.showGUI(100, 500, 800, 500);

        chatClient1 = new ChatClient("Chat 1", this, 100, 100);
        chatClient2 = new ChatClient("Chat 2", this, 500, 100);

        chatClient1.connectToOtherClient(chatClient2);

        log("Application started", null);
    }

    public void log(String message, String clientName) {
        String formattedMessage = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSSSSS")) +
            " - " + (clientName != null ? ('[' + clientName + ']' + ": ") : "") + message;
        activityMonitor.log(formattedMessage);
    }
}
