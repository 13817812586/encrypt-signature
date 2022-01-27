package com.kylewang.encryptsignature.service;

import com.alibaba.fastjson.JSONObject;

import java.security.NoSuchAlgorithmException;

public interface EncryptSignatureService {

    JSONObject generateAESKey() throws NoSuchAlgorithmException;

    JSONObject generateRSAKeys() throws Exception;

}
