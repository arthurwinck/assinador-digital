package com.arthurwinck.assinador.dto;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.cert.X509CertificateHolder;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@Getter
@Setter
public class SigningInfo {
    private PrivateKey privateKey;
    private X509Certificate x509Certificate;
    private List<X509CertificateHolder> certificateHolderList;
    private boolean isSigningAttached;
}
