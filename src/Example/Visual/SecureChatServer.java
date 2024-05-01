package Example.Visual;

import java.io.*;
import java.net.*;
import java.util.concurrent.ConcurrentHashMap;

public class SecureChatServer {
    private ServerSocket serverSocket;
    private ConcurrentHashMap<String, ClientHandler> clients = new ConcurrentHashMap<>();

    public static void main(String[] args) throws IOException {
        SecureChatServer server = new SecureChatServer();
        server.startServer();
    }

    private void startServer() throws IOException {
        serverSocket = new ServerSocket(8080);
        System.out.println("Server started on port 8080.");
        while (true) {
            Socket socket = serverSocket.accept();
            String clientKey = socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
            System.out.println("New client connected from: " + clientKey);
            ClientHandler client = new ClientHandler(socket, clientKey);
            clients.put(clientKey, client);
            new Thread(client).start();
        }
    }

    class ClientHandler implements Runnable {
        private Socket socket;
        private DataInputStream inputStream;
        private DataOutputStream outputStream;
        private String clientKey;

        ClientHandler(Socket socket, String clientKey) throws IOException {
            this.socket = socket;
            this.clientKey = clientKey;
            inputStream = new DataInputStream(socket.getInputStream());
            outputStream = new DataOutputStream(socket.getOutputStream());
            System.out.println("Streams opened for client " + clientKey);
        }

        @Override
        public void run() {
            try {
                while (!socket.isClosed()) {
                    String header = inputStream.readUTF();
                    System.out.println(clientKey + " sent header: " + header);
                    switch (header) {
                        case "PUBLIC_KEY":
                            handlePublicKey();
                            break;
                        case "ENCRYPTED_KEY":
                            handleEncryptedKey();
                            break;
                        case "MESSAGE":
                            handleMessage();
                            break;
                    }
                }
            } catch (IOException e) {
                System.out.println(clientKey + " disconnected: " + e.getMessage());
            } finally {
                closeConnection();
            }
        }

        private void handlePublicKey() throws IOException {
            String publicKey = inputStream.readUTF();
            System.out.println(clientKey + " sent public key: " + publicKey);
            broadcastPublicKey(publicKey);
        }

        private void handleEncryptedKey() throws IOException {
            String encryptedKey = inputStream.readUTF();
            String recipient = inputStream.readUTF();
            System.out.println(clientKey + " sent encrypted key for " + recipient);
            sendEncryptedKey(encryptedKey, recipient);
        }

        private void handleMessage() throws IOException {
            String message = inputStream.readUTF();
            System.out.println(clientKey + " sent message: " + message);
            broadcastMessage(message);
        }

        private void broadcastPublicKey(String publicKey) {
            clients.forEach((key, handler) -> {
                if (!key.equals(clientKey)) {
                    try {
                        handler.outputStream.writeUTF("PUBLIC_KEY");
                        handler.outputStream.writeUTF(publicKey);
                        System.out.println("Broadcasted public key from " + clientKey + " to " + key);
                    } catch (IOException e) {
                        System.out.println("Failed to send public key to " + key + ": " + e.getMessage());
                    }
                }
            });
        }

        private void sendEncryptedKey(String encryptedKey, String recipient) {
            ClientHandler handler = clients.get(recipient);
            if (handler != null) {
                try {
                    handler.outputStream.writeUTF("ENCRYPTED_KEY");
                    handler.outputStream.writeUTF(encryptedKey);
                    System.out.println("Sent encrypted key from " + clientKey + " to " + recipient);
                } catch (IOException e) {
                    System.out.println("Failed to send encrypted key to " + recipient + ": " + e.getMessage());
                }
            }
        }

        private void broadcastMessage(String message) {
            clients.forEach((key, handler) -> {
                if (!key.equals(clientKey)) {
                    try {
                        handler.outputStream.writeUTF("MESSAGE");
                        handler.outputStream.writeUTF(message);
                        System.out.println("Broadcasted message from " + clientKey + " to " + key);
                    } catch (IOException e) {
                        System.out.println("Failed to broadcast message to " + key + ": " + e.getMessage());
                    }
                }
            });
        }

        private void closeConnection() {
            try {
                clients.remove(clientKey);
                socket.close();
                System.out.println("Closed connection for " + clientKey);
            } catch (IOException e) {
                System.out.println("Error closing connection for " + clientKey + ": " + e.getMessage());
            }
        }
    }
}
