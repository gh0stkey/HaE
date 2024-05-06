package hae.utils.string;

import java.security.MessageDigest;

public class HashCalculator {
    public static String calculateHash(byte[] bytes){
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
            byte[] hashBytes = digest.digest(bytes);
            return bytesToHex(hashBytes);
        } catch (Exception ignored) {
            return "";
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
