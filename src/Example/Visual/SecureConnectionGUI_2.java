package Example.Visual;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SecureConnectionGUI_2 {
    private static JTextArea chatArea;
    private static JTextField messageField;
    private static JButton sendButton;

    private static PublicKey user1PublicKey;
    private static PrivateKey user1PrivateKey;
    private static SecretKey symmetricKey;

    private static Socket socket;
    private static DataInputStream inputStream;
    private static DataOutputStream outputStream;

    public static void main(String[] args) throws Exception {
        // Генерация ключевой пары
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Размер ключа
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        user1PublicKey = keyPair.getPublic();
        user1PrivateKey = keyPair.getPrivate();

        // Генерация симметричного ключа
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // Размер ключа
        symmetricKey = keyGenerator.generateKey();

        JFrame frame = new JFrame("Secure Connection");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new BorderLayout());

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(chatArea);

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BorderLayout());
        centerPanel.add(scrollPane, BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BorderLayout());
        messageField = new JTextField();
        sendButton = new JButton("Send");
        sendButton.addActionListener(new SendButtonListener());
        bottomPanel.add(messageField, BorderLayout.CENTER);
        bottomPanel.add(sendButton, BorderLayout.EAST);

        frame.add(centerPanel, BorderLayout.CENTER);
        frame.add(bottomPanel, BorderLayout.SOUTH);

        frame.setVisible(true);

        connectToServer();
    }

    private static void connectToServer() {
        try {
            socket = new Socket("localhost",  8080);
            inputStream = new DataInputStream(socket.getInputStream());
            outputStream = new DataOutputStream(socket.getOutputStream());

            // Отправка публичного ключа
            byte[] publicKeyBytes = user1PublicKey.getEncoded();
            outputStream.writeInt(publicKeyBytes.length);
            outputStream.write(publicKeyBytes);

            // Получение публичного ключа другого пользователя
            int otherPublicKeyLength = inputStream.readInt();
            byte[] otherPublicKeyBytes = new byte[otherPublicKeyLength];
            inputStream.readFully(otherPublicKeyBytes);
            PublicKey otherPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(otherPublicKeyBytes));

            // Отправка зашифрованного симметричного ключа
            byte[] encryptedKey = encryptSymmetricKey(otherPublicKey);
            outputStream.writeInt(encryptedKey.length);
            outputStream.write(encryptedKey);

            // Запуск потока для получения сообщений

            Thread messageReceiverThread = new Thread(new MessageReceiver());
            messageReceiverThread.start();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }
    }

    private static byte[] encryptMessage(String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
            return cipher.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String decryptMessage(byte[] encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] encryptSymmetricKey(PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(symmetricKey.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKey decryptSymmetricKey(byte[] encryptedKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, user1PrivateKey);
            byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
            return new SecretKeySpec(decryptedKeyBytes, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void sendEncryptedMessage(String message) {
        try {
            byte[] encryptedMessage = encryptMessage(message);
            outputStream.writeInt(encryptedMessage.length);
            outputStream.write(encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class SendButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            String message = messageField.getText();
            sendEncryptedMessage(message);
            messageField.setText("");
        }
    }

    private static class MessageReceiver implements Runnable {
        public void run() {
            try {
                while (true) {
                    int encryptedMessageLength = inputStream.readInt();
                    byte[] encryptedMessage = new byte[encryptedMessageLength];
                    inputStream.readFully(encryptedMessage);
                    String decryptedMessage = decryptMessage(encryptedMessage);
                    chatArea.append("Other User: " + decryptedMessage + "\n");
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(0);
            }
        }
    }
}

