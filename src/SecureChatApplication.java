import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

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
        // System.out.println(formattedMessage); // turn of for console logging
    }
}

class ChatClient {
    private JFrame frame;
    private JTextPane chatPane;
    private JTextField messageField;
    private StyledDocument chatDocument;
    private Style styleBold, styleNormal;
    private String clientName;
    private ChatClient otherChatClient;
    private SecureChatApplication app;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey symmetricKey;
    private JPanel bottomPanel;

    public ChatClient(String clientName, SecureChatApplication app, int x, int y) {
        this.clientName = clientName;
        this.app = app;
        initializeGUI(x, y);
        app.log("Initialized chat window for " + clientName, clientName);
    }

    private void initializeGUI(int x, int y) {
        frame = new JFrame(clientName);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new BorderLayout());

        chatPane = new JTextPane();
        chatPane.setEditable(false);
        chatDocument = chatPane.getStyledDocument();

        styleBold = chatDocument.addStyle("BoldStyle", null);
        StyleConstants.setBold(styleBold, true);

        styleNormal = chatDocument.addStyle("NormalStyle", null);
        StyleConstants.setBold(styleNormal, false);

        JScrollPane scrollPane = new JScrollPane(chatPane);
        frame.add(scrollPane, BorderLayout.CENTER);

        bottomPanel = new JPanel(new BorderLayout());
        messageField = new JTextField();
        messageField.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "send");
        messageField.getActionMap().put("send", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });
        bottomPanel.add(messageField, BorderLayout.CENTER);

        JButton sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendMessage());
        bottomPanel.add(sendButton, BorderLayout.EAST);
        frame.setLocation(x, y);
    }

    private void generateAsymmetricKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
            app.log("Generated asymmetric keys for " + clientName +
                "\n    Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                "\n    Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()), clientName);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void connectToOtherClient(ChatClient other) {
        this.otherChatClient = other;
        generateAsymmetricKeys();
        app.log("Initiated connection from " + clientName + " to " + other.clientName +
            "\n    Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()), clientName);
        other.receivePublicKey(this.publicKey, this);
    }

    public void receivePublicKey(PublicKey publicKey, ChatClient otherClient) {
        this.otherChatClient = otherClient;
        app.log(clientName + " received public key from " + otherChatClient.clientName +
            "\n    Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()), clientName);
        this.otherChatClient.publicKey = publicKey;
        generateSymmetricKey();
    }

    private void generateSymmetricKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            this.symmetricKey = keyGen.generateKey();
            app.log("Generated symmetric key for " + clientName +
                "\n    Symmetric Key: " + Base64.getEncoder().encodeToString(symmetricKey.getEncoded()), clientName);
            sendEncryptedSymmetricKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void sendEncryptedSymmetricKey() {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, this.otherChatClient.publicKey);
            byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());
            app.log(clientName + " sent encrypted symmetric key to " + otherChatClient.clientName +
                "\n    Encrypted Symmetric Key: " + Base64.getEncoder().encodeToString(encryptedKey), clientName);
            otherChatClient.receiveEncryptedSymmetricKey(encryptedKey);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public void receiveEncryptedSymmetricKey(byte[] encryptedKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
            this.symmetricKey = new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
            app.log(clientName + " decrypted symmetric key received from " + otherChatClient.clientName +
                "\n    Decrypted Symmetric Key: " + Base64.getEncoder().encodeToString(decryptedKeyBytes), clientName);
            markConnectionEstablished();
            sendConfirmationMessage("rutherfordium");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    private void sendConfirmationMessage(String confirmationMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            app.log(clientName + " encrypting confirmation message to " + otherChatClient.clientName, clientName);
            byte[] encryptedMessage = cipher.doFinal(confirmationMessage.getBytes());
            app.log(clientName + " sending encrypted confirmation message to " + otherChatClient.clientName +
                "\n    Confirmation Message: " + confirmationMessage, clientName);
            otherChatClient.receiveConnectionConfirmation(encryptedMessage);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    private void receiveConnectionConfirmation(byte[] encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            byte[] decryptedMessageBytes = cipher.doFinal(encryptedMessage);
            String decryptedMessage = new String(decryptedMessageBytes);
            app.log(clientName + " received decrypted confirmation message from " + otherChatClient.clientName +
                "\n    Decrypted Message: " + decryptedMessage, clientName);

            if ("rutherfordium".equals(decryptedMessage)) {
                app.log(clientName + " successfully confirmed symmetric key with " + otherChatClient.clientName, clientName);
                markConnectionEstablished();
            } else {
                app.log(clientName + " error in confirming symmetric key with " + otherChatClient.clientName +
                    "\n    Expected 'rutherfordium', but got '" + decryptedMessage + "'", clientName);
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            app.log(clientName + " failed to decrypt confirmation message", clientName);
        }
    }

    public void markConnectionEstablished() {
        app.log("Connection established for " + clientName, clientName);
        SwingUtilities.invokeLater(() -> {
            frame.add(bottomPanel, BorderLayout.SOUTH);
            frame.setVisible(true);
            app.log("Showing GUI for " + clientName, clientName);
            frame.toFront();
            messageField.requestFocusInWindow();
        });
    }

    private String encryptMessage(String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
            app.log("Encrypted message sent: " + encryptedMessage, clientName);
            return encryptedMessage;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    private String decryptMessage(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            String decryptedMessage = new String(decryptedBytes);
            app.log("Decrypted message received: " + decryptedMessage, clientName);
            return decryptedMessage;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void receiveMessage(String encryptedMessage) {
        app.log("Received encrypted message: " + encryptedMessage, clientName);
        String message = decryptMessage(encryptedMessage);
        try {
            chatDocument.insertString(chatDocument.getLength(), otherChatClient.clientName + ": ", styleBold);
            chatDocument.insertString(chatDocument.getLength(), message + "\n", styleNormal);
            StyleConstants.setAlignment(styleNormal, StyleConstants.ALIGN_LEFT);
            chatDocument.setParagraphAttributes(chatDocument.getLength() - message.length() - 1, message.length() + 1, styleNormal, false);
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
    }

    public void sendMessage() {
        String message = messageField.getText().trim();
        app.log("Sending message: " + message, clientName);
        if (!message.isEmpty()) {
            String encryptedMessage = encryptMessage(message);
            try {
                chatDocument.insertString(chatDocument.getLength(), "You: ", styleBold);
                chatDocument.insertString(chatDocument.getLength(), message + "\n", styleNormal);
                StyleConstants.setAlignment(styleNormal, StyleConstants.ALIGN_RIGHT);
                chatDocument.setParagraphAttributes(chatDocument.getLength() - message.length() - 1, message.length() + 1, styleNormal, false);
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
            messageField.setText("");
            otherChatClient.receiveMessage(encryptedMessage);
        }
    }
}

class ActivityMonitor {
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
        logArea.append(message + "\n");
    }
}
