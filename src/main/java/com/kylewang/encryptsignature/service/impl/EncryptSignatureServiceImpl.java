package com.kylewang.encryptsignature.service.impl;

import com.alibaba.fastjson.JSONObject;
import com.kylewang.encryptsignature.service.EncryptSignatureService;
import com.kylewang.encryptsignature.utils.AESUtils;
import com.kylewang.encryptsignature.utils.RSAUtils;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Service
public class EncryptSignatureServiceImpl implements EncryptSignatureService {

    @Override
    public JSONObject generateAESKey() throws NoSuchAlgorithmException {
        JSONObject result = new JSONObject();
        SecretKey secretKey = AESUtils.generateKey(128);
        String key = AESUtils.bytesToHexString(secretKey.getEncoded());
        result.put("aesKey", key);
        return result;
    }

    @Override
    public JSONObject generateRSAKeys() throws Exception {
        JSONObject result = new JSONObject();
        KeyPair keyPair = RSAUtils.generateKeyPair();
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        result.put("rsaPublicKey", publicKey);
        result.put("rsaPrivateKey", privateKey);
        return result;
    }

    @Override
    public void encryptSignatureFlow() throws Exception {
        System.out.println("==================== Preset Data ====================");
        String rawData = "{\"name\": \"Kyle\", \"mobile\": \"138****2586\"}";
        System.out.println("Raw data: " + rawData);
        KeyPair encryptKeyPair = RSAUtils.generateKeyPair();
        KeyPair signKeyPair = RSAUtils.generateKeyPair();
        System.out.println("Encrypt public key: " + Base64.getEncoder().encodeToString(encryptKeyPair.getPublic().getEncoded()));
        System.out.println("Encrypt private key: " + Base64.getEncoder().encodeToString(encryptKeyPair.getPrivate().getEncoded()));
        System.out.println("Signature public key: " + Base64.getEncoder().encodeToString(signKeyPair.getPublic().getEncoded()));
        System.out.println("Signature private key: " + Base64.getEncoder().encodeToString(signKeyPair.getPrivate().getEncoded()));
        System.out.println();

        System.out.println("==================== Client Side ====================");
        // Generate AES key
        SecretKey secretKey = AESUtils.generateKey(128);
        String key = AESUtils.bytesToHexString(secretKey.getEncoded());
        System.out.println("AES key: " + key);
        // Encrypt data with AES key
        String encryptData = AESUtils.encrypt(AESUtils.hexStringToBytes(key), rawData);
        // Signature AES key
        String signature = RSAUtils.sign(key, signKeyPair.getPrivate());
        String encryptKey = RSAUtils.encrypt(key, encryptKeyPair.getPublic());
        JSONObject request = new JSONObject();
        request.put("encryptData", encryptData);
        request.put("encryptKey", encryptKey);
        request.put("signature", signature);
        System.out.println("Request body: " + request);
        System.out.println();

        System.out.println("==================== Server Side ====================");
        // Decrypt key
        String encryptData1 = request.getString("encryptData");
        String encryptKey1 = request.getString("encryptKey");
        String signature1 = request.getString("signature");
        String decryptKey = RSAUtils.decrypt(encryptKey1, encryptKeyPair.getPrivate());
        // Verify signature
        boolean verifyResult = RSAUtils.verify(decryptKey, signature, signKeyPair.getPublic());
        if (verifyResult) {
            String data = AESUtils.decrypt(AESUtils.hexStringToBytes(decryptKey), encryptData1);
            System.out.println("Received request data: " + data);
        }
        System.out.println();
    }
}
