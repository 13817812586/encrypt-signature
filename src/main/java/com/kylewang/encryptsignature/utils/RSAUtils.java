package com.kylewang.encryptsignature.utils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAUtils {

    public static final String RSA_CIPHER = "RSA/ECB/PKCS1Padding";
    public static final String RSA_SIGN = "SHA256withRSA";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        return pair;
    }

    public static PublicKey getPublicKey(String key) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }


    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance(RSA_CIPHER);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decryptCipher = Cipher.getInstance(RSA_CIPHER);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decryptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance(RSA_SIGN);
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance(RSA_SIGN);
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String args[]) throws Exception {
        KeyPair encryptKeyPair = generateKeyPair();
        KeyPair signKeyPair = generateKeyPair();
        System.out.println("Encrypt public key: " + Base64.getEncoder().encodeToString(encryptKeyPair.getPublic().getEncoded()));
        System.out.println("Encrypt private key: " + Base64.getEncoder().encodeToString(encryptKeyPair.getPrivate().getEncoded()));
        System.out.println("Signature public key: " + Base64.getEncoder().encodeToString(signKeyPair.getPublic().getEncoded()));
        System.out.println("Signature private key: " + Base64.getEncoder().encodeToString(signKeyPair.getPrivate().getEncoded()));
        String rawData = "{\"name\": \"Kyle\", \"mobile\": \"138****2586\"}";
        System.out.println("==================== Client Side ====================");
        System.out.println("Raw data: " + rawData);
        String encryptData = encrypt(rawData, encryptKeyPair.getPublic());
        System.out.println("Encrypt data: " + encryptData);
        String signData = sign(encryptData, signKeyPair.getPrivate());
        System.out.println("Signature data: " + signData);
        System.out.println("==================== Server Side ====================");
        boolean verifyResult = verify(encryptData, signData, signKeyPair.getPublic());
        System.out.println("Signature verify result: " + verifyResult);
        String decryptData = decrypt(encryptData, encryptKeyPair.getPrivate());
        System.out.println("Decrypt data: " + decryptData);
    }
}