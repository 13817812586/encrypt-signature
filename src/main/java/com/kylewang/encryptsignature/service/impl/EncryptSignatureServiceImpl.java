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
}
