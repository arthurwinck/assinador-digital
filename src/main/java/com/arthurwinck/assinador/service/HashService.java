package com.arthurwinck.assinador.service;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class HashService {

    public String generateHexEncodedHash(String string) {
        SHA256Digest digest = new SHA256Digest();

        digest.update(string.getBytes(StandardCharsets.UTF_8), 0, string.length());

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return new String(Hex.encode(hash));
    }
}
