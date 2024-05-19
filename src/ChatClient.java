import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.dnd.*;
import java.awt.event.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;

public class ChatClient {
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
                            if (ImageUtils.isImageFile(file)) {
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
                return ImageUtils.isImageFile(f);
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

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public SecretKey getSymmetricKey() {
        return symmetricKey;
    }

    public ChatClient getOtherChatClient() {
        return otherChatClient;
    }

    public String getClientName() {
        return clientName;
    }

    public SecureChatApplication getApp() {
        return app;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setSymmetricKey(SecretKey symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

    public void connectToOtherClient(ChatClient other) {
        this.otherChatClient = other;
        CryptoUtils.generateAsymmetricKeys(this);
        app.log("Initiated connection from " + clientName + " to " + other.getClientName() +
            "\n    Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()), clientName);
        other.receivePublicKey(this.publicKey, this);
    }

    public void receivePublicKey(PublicKey publicKey, ChatClient otherClient) {
        this.otherChatClient = otherClient;
        app.log(clientName + " received public key from " + otherChatClient.getClientName() +
            "\n    Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()), clientName);
        this.otherChatClient.publicKey = publicKey;
        CryptoUtils.generateSymmetricKey(this);
    }

    public void receiveEncryptedSymmetricKey(byte[] encryptedKey) {
        try {
            this.symmetricKey = CryptoUtils.decryptSymmetricKey(encryptedKey, privateKey);
            app.log(clientName + " decrypted symmetric key received from " + otherChatClient.getClientName() +
                "\n    Decrypted Symmetric Key: " + Base64.getEncoder().encodeToString(symmetricKey.getEncoded()), clientName);
            markConnectionEstablished();
            sendConfirmationMessage("rutherfordium");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    private void sendConfirmationMessage(String confirmationMessage) {
        try {
            byte[] encryptedMessage = CryptoUtils.encryptMessage(confirmationMessage.getBytes(), symmetricKey);
            app.log(clientName + " encrypting confirmation message to " + otherChatClient.getClientName(), clientName);
            app.log(clientName + " sending encrypted confirmation message to " + otherChatClient.getClientName() +
                "\n    Confirmation Message: " + confirmationMessage, clientName);
            otherChatClient.receiveConnectionConfirmation(encryptedMessage);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    private void receiveConnectionConfirmation(byte[] encryptedMessage) {
        try {
            byte[] decryptedMessageBytes = CryptoUtils.decryptMessage(encryptedMessage, symmetricKey);
            String decryptedMessage = new String(decryptedMessageBytes);
            app.log(clientName + " received decrypted confirmation message from " + otherChatClient.getClientName() +
                "\n    Decrypted Message: " + decryptedMessage, clientName);

            if ("rutherfordium".equals(decryptedMessage)) {
                app.log(clientName + " successfully confirmed symmetric key with " + otherChatClient.getClientName(), clientName);
                markConnectionEstablished();
            } else {
                app.log(clientName + " error in confirming symmetric key with " + otherChatClient.getClientName() +
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
            byte[] encryptedBytes = CryptoUtils.encryptMessage(message, symmetricKey);
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
            byte[] decryptedBytes = CryptoUtils.decryptMessage(Base64.getDecoder().decode(encryptedMessage), symmetricKey);
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
                    chatDocument.insertString(chatDocument.getLength(), otherChatClient.getClientName() + ": ", styleBold);
                    chatDocument.insertString(chatDocument.getLength(), message + "\n", styleNormal);
                    StyleConstants.setAlignment(styleNormal, StyleConstants.ALIGN_LEFT);
                    chatDocument.setParagraphAttributes(chatDocument.getLength() - message.length() - 1, message.length() + 1, styleNormal, false);
                } else if ("image".equals(type)) {
                    ImageIcon imageIcon = new ImageIcon(messageBytes);
                    chatDocument.insertString(chatDocument.getLength(), otherChatClient.getClientName() + ": ", styleBold);
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

    public void sendImage(Image image) {
        try {
            byte[] encryptedImageBytes = ImageUtils.encryptImage(image, symmetricKey);
            app.log("Image encryption complete, sending image", clientName);
            ImageUtils.displayImage(chatDocument, chatPane, ImageUtils.convertToBufferedImage(image), "You");
            otherChatClient.receiveEncryptedImage(encryptedImageBytes);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    public void receiveEncryptedImage(byte[] encryptedImageBytes) {
        app.log("Received encrypted image data", clientName);
        ImageUtils.decryptAndDisplayImage(encryptedImageBytes, symmetricKey, chatDocument, chatPane, otherChatClient.getClientName());
    }
}
