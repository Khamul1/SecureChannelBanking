package Example.Visual;

import java.io.*;
import java.net.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
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
        System.out.println("[" + getCurrentTimestamp() + "] Server started on port 8080.");
        while (true) {
            Socket socket = serverSocket.accept();
            String clientKey = socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
            System.out.println("[" + getCurrentTimestamp() + "] New client connected from: " + clientKey);
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
            System.out.println("[" + getCurrentTimestamp() + "] Streams opened for client " + clientKey);
        }

        @Override
        public void run() {
            try {
                while (!socket.isClosed()) {
                    String header = inputStream.readUTF();
                    System.out.println("[" + getCurrentTimestamp() + "] " + clientKey + " sent header: " + header);
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
                System.out.println("[" + getCurrentTimestamp() + "] " + clientKey + " disconnected: " + e.getMessage());
            } finally {
                closeConnection();
            }
        }

        private void handlePublicKey() throws IOException {
            String publicKey = inputStream.readUTF();
            System.out.println("[" + getCurrentTimestamp() + "] " + clientKey + " sent public key: " + publicKey);
            broadcastPublicKey(publicKey);
        }

        private void handleEncryptedKey() throws IOException {
            String encryptedKey = inputStream.readUTF();
            String recipient = inputStream.readUTF();
            System.out.println("[" + getCurrentTimestamp() + "] " + clientKey + " sent encrypted key for " + recipient);
            sendEncryptedKey(encryptedKey, recipient);
        }

        private void handleMessage() throws IOException {
            String message = inputStream.readUTF();

            System.out.println("[" + getCurrentTimestamp() + "] " + clientKey + " sent message: " + message);
            broadcastMessage(message);
        }

        private void broadcastPublicKey(String publicKey) {
            clients.forEach((key, handler) -> {
                if (!key.equals(clientKey)) {
                    try {
                        handler.outputStream.writeUTF("PUBLIC_KEY");
                        handler.outputStream.writeUTF(publicKey);
                        System.out.println("[" + getCurrentTimestamp() + "] Broadcasted public key from " + clientKey + " to " + key);
                    } catch (IOException e) {
                        System.out.println("[" + getCurrentTimestamp() + "] Failed to send public key to " + key + ": " + e.getMessage());
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
                    handler.outputStream.writeUTF(clientKey);
                } catch (IOException e) {
                    System.out.println("[" + getCurrentTimestamp() + "] Failed to send encrypted key to " + recipient + ": " + e.getMessage());
                }
            } else {
                System.out.println("[" + getCurrentTimestamp() + "] Recipient " + recipient + " not found.");
            }
        }

        private void broadcastMessage(String message) {
            clients.forEach((key, handler) -> {
                if (!key.equals(clientKey)) {
                    try {
                        handler.outputStream.writeUTF("MESSAGE");
                        handler.outputStream.writeUTF(message);
                        handler.outputStream.writeUTF(clientKey);
                    } catch (IOException e) {
                        System.out.println("[" + getCurrentTimestamp() + "] Failed to send message to " + key + ": " + e.getMessage());
                    }
                }
            });
        }

        private void closeConnection() {
            try {
                inputStream.close();
            } catch (IOException e) {
                System.out.println("[" + getCurrentTimestamp() + "] Failed to close input stream for " + clientKey + ": " + e.getMessage());
            }
            try {
                outputStream.close();
            } catch (IOException e) {
                System.out.println("[" + getCurrentTimestamp() + "] Failed to close output stream for " + clientKey + ": " + e.getMessage());
            }
            try {
                socket.close();
            } catch (IOException e) {
                System.out.println("[" + getCurrentTimestamp() + "] Failed to close socket for " + clientKey + ": " + e.getMessage());
            }
            clients.remove(clientKey);
        }
    }

    private String getCurrentTimestamp() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
        return LocalDateTime.now().format(formatter);
    }
}
