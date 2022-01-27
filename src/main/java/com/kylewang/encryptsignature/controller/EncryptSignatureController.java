package com.kylewang.encryptsignature.controller;

import com.alibaba.fastjson.JSONObject;
import com.kylewang.encryptsignature.service.EncryptSignatureService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;

@RestController
public class EncryptSignatureController {

    @Autowired
    EncryptSignatureService encryptSignatureService;

    @GetMapping("/generateAESKey")
    public JSONObject generateAESKey() throws NoSuchAlgorithmException {
        return encryptSignatureService.generateAESKey();
    }

    @GetMapping("/generateRSAKeys")
    public JSONObject generateRSAKeys() throws Exception {
        return encryptSignatureService.generateRSAKeys();
    }

    @GetMapping("/encryptSignatureFlow")
    public void encryptSignatureFlow() throws Exception {
        encryptSignatureService.encryptSignatureFlow();
    }
}
