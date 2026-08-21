package com.example.cbom;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class AuthService {
    public KeyPair generateJwtRsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public byte[] signJwtLikePayload(byte[] payload, PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(payload);
        return signature.sign();
    }

    public KeyPair generateEcKeyForTlsLikeUse() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }
}
