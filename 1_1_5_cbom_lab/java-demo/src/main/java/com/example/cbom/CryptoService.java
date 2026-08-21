package com.example.cbom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoService {
    public byte[] encryptAesGcm(byte[] plaintext, byte[] aad) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey key = kg.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    public byte[] legacySha1(byte[] data) throws Exception {
        // INTENTIONAL: legacy algorithm for CBOM risk-detection exercise.
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    public String hmacSha256(String msg, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(msg.getBytes()));
    }
}
