import javax.swing.*;
import java.awt.*;

public class ActivityMonitor {
    private JFrame frame;
    private JTextArea logArea;

    public ActivityMonitor() {
        frame = new JFrame("Activity Monitor");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(logArea);
        frame.add(scrollPane, BorderLayout.CENTER);
    }

    public void showGUI(int x, int y, int width, int height) {
        frame.setBounds(x, y, width, height);
        frame.setVisible(true);
    }

    public void log(String message) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
}
