package Example.Visual;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;

public class SecureConnectionGUI {
    private JFrame frame;
    private JTextArea chatArea;
    private JTextField messageField;
    private JButton sendButton;

    private Socket socket;
    private DataInputStream inputStream;
    private DataOutputStream outputStream;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecretKey symmetricKey;
    private Cipher aesCipher;

    public static void main(String[] args) {
        new SecureConnectionGUI().initGUI();
    }

    private void initGUI() {
        frame = new JFrame("Secure Connection");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new BorderLayout());

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        messageField = new JTextField();
        sendButton = new JButton("Send");
        sendButton.addActionListener(this::sendButtonAction);

        bottomPanel.add(messageField, BorderLayout.CENTER);
        bottomPanel.add(sendButton, BorderLayout.EAST);

        frame.add(scrollPane, BorderLayout.CENTER);
        frame.add(bottomPanel, BorderLayout.SOUTH);

        frame.setVisible(true);

        setupConnection();
        generateKeys();
        sendPublicKey();
    }

    private void setupConnection() {
        try {
            socket = new Socket("localhost", 8080);
            inputStream = new DataInputStream(socket.getInputStream());
            outputStream = new DataOutputStream(socket.getOutputStream());
            System.out.println("Connection established with the server. Ready to communicate.");
        } catch (IOException e) {
            System.err.println("Failed to establish connection with the server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void generateKeys() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();

            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);  // 128-bit AES
            symmetricKey = keyGenerator.generateKey();

            aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(new byte[16]));  // Zero IV for simplicity in example

            System.out.println("Asymmetric and symmetric keys have been generated successfully.");
        } catch (GeneralSecurityException e) {
            System.err.println("Key generation error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void sendPublicKey() {
        try {
            byte[] publicKeyBytes = publicKey.getEncoded();
            String encodedPublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
            outputStream.writeUTF("PUBLIC_KEY");
            outputStream.writeUTF(encodedPublicKey);
            System.out.println("Public key sent: " + encodedPublicKey);
        } catch (IOException e) {
            System.err.println("Error sending public key: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void sendButtonAction(ActionEvent e) {
        try {
            String message = messageField.getText();
            byte[] encryptedMessage = aesCipher.doFinal(message.getBytes());
            String base64EncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
            outputStream.writeUTF("MESSAGE");
            outputStream.writeUTF(base64EncryptedMessage);
            chatArea.append("Me: " + message + "\n");
            messageField.setText("");
            System.out.println("Encrypted message sent: " + base64EncryptedMessage);
        } catch (Exception ex) {
            System.err.println("Error encrypting or sending message: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private void listenForMessages() {
        try {
            while (true) {
                String header = inputStream.readUTF();
                if ("PUBLIC_KEY".equals(header)) {
                    String base64PublicKey = inputStream.readUTF();
                    handlePublicKey(base64PublicKey);
                } else if ("ENCRYPTED_KEY".equals(header)) {
                    String base64EncryptedKey = inputStream.readUTF();
                    handleEncryptedKey(base64EncryptedKey);
                } else if ("MESSAGE".equals(header)) {
                    String encryptedMessage = inputStream.readUTF();
                    handleMessage(encryptedMessage);
                }
            }
        } catch (IOException e) {
            System.err.println("Error receiving messages: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void handlePublicKey(String base64PublicKey) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
            PublicKey otherPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            System.out.println("Received public key, preparing to send encrypted symmetric key.");
            sendEncryptedSymmetricKey(otherPublicKey);
        } catch (GeneralSecurityException e) {
            System.err.println("Error handling public key: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void sendEncryptedSymmetricKey(PublicKey otherPublicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, otherPublicKey);
            byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());
            String base64EncryptedKey = Base64.getEncoder().encodeToString(encryptedKey);
            outputStream.writeUTF("ENCRYPTED_KEY");
            outputStream.writeUTF(base64EncryptedKey);
            System.out.println("Encrypted symmetric key sent: " + base64EncryptedKey);
        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Error sending encrypted symmetric key: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleEncryptedKey(String base64EncryptedKey) {
        try {
            byte[] encryptedKey = Base64.getDecoder().decode(base64EncryptedKey);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] keyBytes = cipher.doFinal(encryptedKey);
            symmetricKey = new SecretKeySpec(keyBytes, "AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(new byte[16]));  // Re-initialize aesCipher with new key
            System.out.println("Symmetric key decrypted and updated for secure communication.");
        } catch (GeneralSecurityException e) {
            System.err.println("Error decrypting symmetric key: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleMessage(String encryptedMessage) {
        try {
            byte[] cipherText = Base64.getDecoder().decode(encryptedMessage);
            aesCipher.init(Cipher.DECRYPT_MODE, symmetricKey, new IvParameterSpec(new byte[16]));  // Same IV should be used as was used for encryption
            String message = new String(aesCipher.doFinal(cipherText));
            chatArea.append("Other: " + message + "\n");
            System.out.println("Decrypted message received and displayed: " + message);
        } catch (GeneralSecurityException e) {
            System.err.println("Error decrypting message: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
