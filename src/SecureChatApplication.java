import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.awt.event.*;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.awt.Graphics2D;

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
        // System.out.println(formattedMessage); // turn off for console logging
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
    private JButton sendButton, imageButton;

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

        sendButton = new JButton("Send");
        sendButton.addActionListener(e -> sendMessage());
        bottomPanel.add(sendButton, BorderLayout.EAST);

        imageButton = new JButton("Send Image");
        imageButton.addActionListener(e -> selectAndSendImage());
        bottomPanel.add(imageButton, BorderLayout.WEST);

        frame.setLocation(x, y);
        frame.add(bottomPanel, BorderLayout.SOUTH);

        // Enable drag-and-drop for images
        new DropTarget(chatPane, new DropTargetAdapter() {
            @Override
            public void drop(DropTargetDropEvent dtde) {
                try {
                    dtde.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable t = dtde.getTransferable();
                    if (t.isDataFlavorSupported(DataFlavor.imageFlavor)) {
                        Image image = (Image) t.getTransferData(DataFlavor.imageFlavor);
                        sendImage(image);
                    } else if (t.isDataFlavorSupported(DataFlavor.javaFileListFlavor)) {
                        java.util.List<File> files = (java.util.List<File>) t.getTransferData(DataFlavor.javaFileListFlavor);
                        for (File file : files) {
                            if (isImageFile(file)) {
                                Image image = ImageIO.read(file);
                                sendImage(image);
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private void selectAndSendImage() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                if (f.isDirectory()) {
                    return true;
                }
                String name = f.getName().toLowerCase();
                return name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".png") || name.endsWith(".gif") || name.endsWith(".bmp");
            }

            @Override
            public String getDescription() {
                return "Image Files";
            }
        });

        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                BufferedImage image = ImageIO.read(file);
                sendImage(image);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private boolean isImageFile(File file) {
        String[] imageExtensions = { "png", "jpg", "jpeg", "gif", "bmp" };
        String fileName = file.getName().toLowerCase();
        for (String ext : imageExtensions) {
            if (fileName.endsWith(ext)) {
                return true;
            }
        }
        return false;
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
            frame.setVisible(true);
            app.log("Showing GUI for " + clientName, clientName);
            frame.toFront();
            messageField.requestFocusInWindow();
        });
    }

    private String encryptMessage(byte[] message) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            byte[] encryptedBytes = cipher.doFinal(message);
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
            app.log("Message encrypted: " + encryptedMessage, clientName);
            return encryptedMessage;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    private byte[] decryptMessage(String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            app.log("Message decrypted: " + new String(decryptedBytes), clientName);
            return decryptedBytes;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void receiveMessage(String encryptedMessage, String type) {
        app.log("Received encrypted message: " + encryptedMessage, clientName);
        byte[] messageBytes = decryptMessage(encryptedMessage);
        if (messageBytes == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            try {
                if ("text".equals(type)) {
                    String message = new String(messageBytes);
                    chatDocument.insertString(chatDocument.getLength(), otherChatClient.clientName + ": ", styleBold);
                    chatDocument.insertString(chatDocument.getLength(), message + "\n", styleNormal);
                    StyleConstants.setAlignment(styleNormal, StyleConstants.ALIGN_LEFT);
                    chatDocument.setParagraphAttributes(chatDocument.getLength() - message.length() - 1, message.length() + 1, styleNormal, false);
                } else if ("image".equals(type)) {
                    ImageIcon imageIcon = new ImageIcon(messageBytes);
                    chatDocument.insertString(chatDocument.getLength(), otherChatClient.clientName + ": ", styleBold);
                    chatPane.setCaretPosition(chatDocument.getLength());
                    chatPane.insertIcon(imageIcon);
                    chatDocument.insertString(chatDocument.getLength(), "\n", styleNormal);
                    StyleConstants.setAlignment(styleNormal, StyleConstants.ALIGN_LEFT);
                }
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
        });
    }

    public void sendMessage() {
        String message = messageField.getText().trim();
        app.log("Sending message: " + message, clientName);
        if (!message.isEmpty()) {
            byte[] messageBytes = message.getBytes();
            String encryptedMessage = encryptMessage(messageBytes);
            try {
                chatDocument.insertString(chatDocument.getLength(), "You: ", styleBold);
                chatDocument.insertString(chatDocument.getLength(), message + "\n", styleNormal);
                StyleConstants.setAlignment(styleNormal, StyleConstants.ALIGN_RIGHT);
                chatDocument.setParagraphAttributes(chatDocument.getLength() - message.length() - 1, message.length() + 1, styleNormal, false);
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
            messageField.setText("");
            otherChatClient.receiveMessage(encryptedMessage, "text");
        }
    }

    public void sendImage() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new javax.swing.filechooser.FileFilter() {
            @Override
            public boolean accept(File f) {
                if (f.isDirectory()) {
                    return true;
                }
                String name = f.getName().toLowerCase();
                return name.endsWith(".jpg") || name.endsWith(".jpeg") || name.endsWith(".png") || name.endsWith(".gif") || name.endsWith(".bmp");
            }

            @Override
            public String getDescription() {
                return "Image Files";
            }
        });

        int returnValue = fileChooser.showOpenDialog(frame);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                byte[] imageBytes = Files.readAllBytes(file.toPath());
                sendImage(imageBytes);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void sendImage(byte[] imageBytes) {
        String encryptedMessage = encryptMessage(imageBytes);
        try {
            chatDocument.insertString(chatDocument.getLength(), "You: ", styleBold);
            chatPane.setCaretPosition(chatDocument.getLength());
            chatPane.insertIcon(new ImageIcon(imageBytes));
            chatDocument.insertString(chatDocument.getLength(), "\n", styleNormal);
            StyleConstants.setAlignment(styleNormal, StyleConstants.ALIGN_RIGHT);
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
        otherChatClient.receiveMessage(encryptedMessage, "image");
    }

    public void sendImage(Image image) {
        try {
            app.log("Starting image conversion to BufferedImage", clientName);
    
            BufferedImage bufferedImage = new BufferedImage(image.getWidth(null), image.getHeight(null), BufferedImage.TYPE_INT_ARGB);
            Graphics2D g2 = bufferedImage.createGraphics();
            g2.drawImage(image, 0, 0, null);
            g2.dispose();
    
            app.log("Image converted to BufferedImage, starting encryption", clientName);
    
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(bufferedImage, "png", baos);
            byte[] imageBytes = baos.toByteArray();
    
            int totalBytes = imageBytes.length;
            int processedBytes = 0;
    
            ByteArrayOutputStream encryptedBaos = new ByteArrayOutputStream();
    
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
    
            long startTime = System.currentTimeMillis();
            for (int i = 0; i < totalBytes; ) {
                int chunkSize = Math.min(1024, totalBytes - i);
                byte[] chunk = cipher.update(imageBytes, i, chunkSize);
                if (chunk != null) {
                    encryptedBaos.write(chunk);
                }
                processedBytes += chunkSize;
                i += chunkSize;
    
                long currentTime = System.currentTimeMillis();
                if (currentTime - startTime >= 1000) {
                    app.log("Encryption progress: " + (processedBytes * 100 / totalBytes) + "%", clientName);
                    startTime = currentTime;
                }
            }
    
            byte[] finalChunk = cipher.doFinal();
            if (finalChunk != null) {
                encryptedBaos.write(finalChunk);
            }
    
            byte[] encryptedImageBytes = encryptedBaos.toByteArray();
            app.log("Image encryption complete, sending image", clientName);
    
            displayImage(bufferedImage, "You");
    
            otherChatClient.receiveEncryptedImage(encryptedImageBytes);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    public void receiveEncryptedImage(byte[] encryptedImageBytes) {
        app.log("Received encrypted image data", clientName);
        decryptAndDisplayImage(encryptedImageBytes);
    }

    public void decryptAndDisplayImage(byte[] encryptedImageBytes) {
        try {
            app.log("Starting image decryption", clientName);

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);

            int totalBytes = encryptedImageBytes.length;
            int processedBytes = 0;

            ByteArrayOutputStream decryptedBaos = new ByteArrayOutputStream();

            long startTime = System.currentTimeMillis();
            for (int i = 0; i < totalBytes; ) {
                int chunkSize = Math.min(1024, totalBytes - i);
                byte[] chunk = cipher.update(encryptedImageBytes, i, chunkSize);
                if (chunk != null) {
                    decryptedBaos.write(chunk);
                }
                processedBytes += chunkSize;
                i += chunkSize;

                long currentTime = System.currentTimeMillis();
                if (currentTime - startTime >= 1000) {
                    app.log("Decryption progress: " + (processedBytes * 100 / totalBytes) + "%", clientName);
                    startTime = currentTime;
                }
            }

            byte[] finalChunk = cipher.doFinal();
            if (finalChunk != null) {
                decryptedBaos.write(finalChunk);
            }

            byte[] decryptedImageBytes = decryptedBaos.toByteArray();
            ByteArrayInputStream bais = new ByteArrayInputStream(decryptedImageBytes);
            BufferedImage bufferedImage = ImageIO.read(bais);

            app.log("Image decryption complete, rendering image", clientName);

            displayImage(bufferedImage, otherChatClient.clientName);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    private void displayImage(BufferedImage image, String sender) {
        JLabel picLabel = new JLabel(new ImageIcon(image));
        SwingUtilities.invokeLater(() -> {
            try {
                boolean isSender = sender.equals("You");
    
                chatDocument.insertString(chatDocument.getLength(), sender + ": ", styleBold);
                chatDocument.insertString(chatDocument.getLength(), "\n", styleNormal); // Add a newline before the image
                chatPane.setCaretPosition(chatDocument.getLength());
                chatPane.insertComponent(picLabel);
                chatDocument.insertString(chatDocument.getLength(), "\n", styleNormal); // Add a newline after the image
    
                Style alignment = chatDocument.addStyle("alignment", null);
                StyleConstants.setAlignment(alignment, isSender ? StyleConstants.ALIGN_RIGHT : StyleConstants.ALIGN_LEFT);
                chatDocument.setParagraphAttributes(chatDocument.getLength() - 1, 1, alignment, false);
    
                // Apply alignment to the entire paragraph containing the sender label and image
                int start = chatDocument.getLength() - (sender.length() + 3) - 1; // sender + ": " + newline
                int length = chatDocument.getLength() - start;
                chatDocument.setParagraphAttributes(start, length, alignment, false);
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
        });
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
        SwingUtilities.invokeLater(() -> {
            logArea.append(message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }
}
