package com.example.cbom;

import javax.net.ssl.SSLContext;
import java.security.KeyStore;

public class TlsConfig {
    public SSLContext buildLegacyTlsContext() throws Exception {
        // INTENTIONAL: TLSv1.2 for policy review exercise.
        SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(null, null, null);
        return ctx;
    }

    public KeyStore loadPkcs12Keystore() throws Exception {
        return KeyStore.getInstance("PKCS12");
    }
}
