import javax.crypto.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.security.GeneralSecurityException;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.text.*;

public class ImageUtils {
    public static boolean isImageFile(File file) {
        String[] imageExtensions = { "png", "jpg", "jpeg", "gif", "bmp" };
        String fileName = file.getName().toLowerCase();
        for (String ext : imageExtensions) {
            if (fileName.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    public static BufferedImage convertToBufferedImage(Image image) {
        BufferedImage bufferedImage = new BufferedImage(image.getWidth(null), image.getHeight(null), BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = bufferedImage.createGraphics();
        g2.drawImage(image, 0, 0, null);
        g2.dispose();
        return bufferedImage;
    }

    public static byte[] encryptImage(Image image, SecretKey symmetricKey) throws GeneralSecurityException, IOException {
        BufferedImage bufferedImage = convertToBufferedImage(image);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(bufferedImage, "png", baos);
        byte[] imageBytes = baos.toByteArray();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
        return cipher.doFinal(imageBytes);
    }

    public static void decryptAndDisplayImage(byte[] encryptedImageBytes, SecretKey symmetricKey, StyledDocument chatDocument, JTextPane chatPane, String sender) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
            byte[] decryptedImageBytes = cipher.doFinal(encryptedImageBytes);
            ByteArrayInputStream bais = new ByteArrayInputStream(decryptedImageBytes);
            BufferedImage bufferedImage = ImageIO.read(bais);
            displayImage(chatDocument, chatPane, bufferedImage, sender);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void displayImage(StyledDocument chatDocument, JTextPane chatPane, BufferedImage image, String sender) {
        JLabel picLabel = new JLabel(new ImageIcon(image));
        SwingUtilities.invokeLater(() -> {
            try {
                boolean isSender = sender.equals("You");
                Style styleBold = chatDocument.addStyle("BoldStyle", null);
                StyleConstants.setBold(styleBold, true);

                chatDocument.insertString(chatDocument.getLength(), sender + ": ", styleBold);
                chatDocument.insertString(chatDocument.getLength(), "\n", styleBold); 
                chatPane.setCaretPosition(chatDocument.getLength());
                chatPane.insertComponent(picLabel);
                chatDocument.insertString(chatDocument.getLength(), "\n", styleBold); 

                Style alignment = chatDocument.addStyle("alignment", null);
                StyleConstants.setAlignment(alignment, isSender ? StyleConstants.ALIGN_RIGHT : StyleConstants.ALIGN_LEFT);
                chatDocument.setParagraphAttributes(chatDocument.getLength() - 1, 1, alignment, false);

                // Apply alignment to the entire paragraph containing the sender label and image
                int start = chatDocument.getLength() - (sender.length() + 3) - 1;
                int length = chatDocument.getLength() - start;
                chatDocument.setParagraphAttributes(start, length, alignment, false);
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
        });
    }
}
