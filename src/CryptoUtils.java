import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class CryptoUtils {
    public static void generateAsymmetricKeys(ChatClient client) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            client.setPrivateKey(pair.getPrivate()); // Use setter method
            client.setPublicKey(pair.getPublic()); // Use setter method
            client.getApp().log("Generated asymmetric keys for " + client.getClientName() +
                "\n    Public Key: " + Base64.getEncoder().encodeToString(client.getPublicKey().getEncoded()) +
                "\n    Private Key: " + Base64.getEncoder().encodeToString(client.getPrivateKey().getEncoded()), client.getClientName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void generateSymmetricKey(ChatClient client) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            client.setSymmetricKey(keyGen.generateKey()); // Use setter method
            client.getApp().log("Generated symmetric key for " + client.getClientName() +
                "\n    Symmetric Key: " + Base64.getEncoder().encodeToString(client.getSymmetricKey().getEncoded()), client.getClientName());
            sendEncryptedSymmetricKey(client);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void sendEncryptedSymmetricKey(ChatClient client) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, client.getOtherChatClient().getPublicKey());
            byte[] encryptedKey = cipher.doFinal(client.getSymmetricKey().getEncoded());
            client.getApp().log(client.getClientName() + " sent encrypted symmetric key to " + client.getOtherChatClient().getClientName() +
                "\n    Encrypted Symmetric Key: " + Base64.getEncoder().encodeToString(encryptedKey), client.getClientName());
            client.getOtherChatClient().receiveEncryptedSymmetricKey(encryptedKey);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
    }

    public static byte[] encryptMessage(byte[] message, SecretKey symmetricKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
        return cipher.doFinal(message);
    }

    public static byte[] decryptMessage(byte[] encryptedMessage, SecretKey symmetricKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
        return cipher.doFinal(encryptedMessage);
    }
}
