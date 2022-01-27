package com.kylewang.encryptsignature.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class AESUtils {

    public static final String AES_CIPHER = "AES/CBC/PKCS5Padding";

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static String encrypt(byte[] key, String raw) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] enCodeFormat = secretKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        IvParameterSpec iv = new IvParameterSpec(key);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
        byte[] result = cipher.doFinal(raw.getBytes());
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(result);
    }

    public static String decrypt(byte[] key, String enc) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        byte[] enCodeFormat = secretKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, "AES");
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        IvParameterSpec iv = new IvParameterSpec(key);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] result = cipher.doFinal(decoder.decode(enc));
        return new String(result);
    }

    public static String bytesToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String strHex = Integer.toHexString(bytes[i]);
            if (strHex.length() > 3) {
                sb.append(strHex.substring(6));
            } else {
                if (strHex.length() < 2) {
                    sb.append("0" + strHex);
                } else {
                    sb.append(strHex);
                }
            }
        }
        return sb.toString();
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString != null && !hexString.equals("")) {
            hexString = hexString.toUpperCase();
            int length = hexString.length() / 2;
            char[] hexChars = hexString.toCharArray();
            byte[] data = new byte[length];
            for (int i = 0; i < length; ++i) {
                int pos = i * 2;
                data[i] = (byte)(charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
            }
            return data;
        } else {
            return null;
        }
    }

    public static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    public static void main(String[] args) throws Exception {
        SecretKey secretKey = generateKey(128);
        String key = bytesToHexString(secretKey.getEncoded());
        System.out.println("AES key: " + key);
        String rawData = "{\"name\": \"Kyle\", \"mobile\": \"138****2586\"}";
        System.out.println("Raw data: " + rawData);
        String encryptData = encrypt(hexStringToBytes(key), rawData);
        System.out.println("Encrypt data: " + encryptData);
        String decryptData = decrypt(hexStringToBytes(key), encryptData);
        System.out.println("Decrypt data: " + decryptData);
    }
}
