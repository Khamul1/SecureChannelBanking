package Example.Visual;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SecureChatServer {
    private ServerSocket serverSocket;
    private static ArrayList<SecureChatClientThread> clients;

    public static void main(String[] args) throws Exception {
        SecureChatServer server = new SecureChatServer();
        server.startServer();
    }

    private void startServer() throws Exception {
        clients = new ArrayList<>();
        serverSocket = new ServerSocket(8080);
        System.out.println("Server started on port 8080");

        while (true) {
            Socket socket = serverSocket.accept();
            SecureChatClientThread clientThread = new SecureChatClientThread(socket, this);
            clients.add(clientThread);
            clientThread.start();
        }
    }

    public void broadcastMessage(String message, SecureChatClientThread sender) {
        for (SecureChatClientThread client : clients) {
            if (client != sender) {
                client.sendMessage(message);
            }
        }
    }

    private static class SecureChatClientThread extends Thread {
        private Socket socket;
        private DataInputStream inputStream;
        private DataOutputStream outputStream;
        private SecureChatServer server;

        public SecureChatClientThread(Socket socket, SecureChatServer server) {
            this.socket = socket;
            this.server = server;
        }

        public void run() {
            try {
                inputStream = new DataInputStream(socket.getInputStream());
                outputStream = new DataOutputStream(socket.getOutputStream());

                // Обработка соединения и обмен ключами

                // Отправка и получение сообщений


                while (true) {
                    int encryptedMessageLength = inputStream.readInt();
                    byte[] encryptedMessage = new byte[encryptedMessageLength];
                    inputStream.readFully(encryptedMessage); server.broadcastMessage(new String(encryptedMessage), this);
                }
            } catch (Exception e) {
                e.printStackTrace();
                try {
                    socket.close();
                    clients.remove(this);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }

        public void sendMessage(String message) {
            try {
                byte[] encryptedMessage = message.getBytes();
                outputStream.writeInt(encryptedMessage.length);
                outputStream.write(encryptedMessage);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}