package com.arthurwinck.assinador.service;

import com.arthurwinck.assinador.dto.SigningInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Component
public class SigningService {

    private final static String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private final static String CERT_KEY_FILE_FORMAT = "PKCS12";

    // Documento ou conteúdo assinado deve estar anexado na estrutura da própria assinatura
    public String signAttached(String string, Resource pkcs12File, String password) throws Exception {
        SigningInfo signingInfo = SigningService.getSigningInfo(pkcs12File, password);
        signingInfo.setSigningAttached(true);

        CMSSignedData signedString = this.sign(string, signingInfo);

        byte[] bytes = signedString.getEncoded();
        return Base64.toBase64String(bytes);
    }

    // TODO - Handle exceptions later
    private CMSSignedData sign(String string, SigningInfo signingInfo) throws Exception {
        // Cria a estrutura que contém os certificados que serão utilizados
        Store<X509CertificateHolder> jcaCertificateHolderStore = new CollectionStore<>(signingInfo.getCertificateHolderList());
        JcaCertStoreBuilder certStore = new JcaCertStoreBuilder().addCertificates(jcaCertificateHolderStore);

        // Engine de assinatura, usando SHA512withRSA
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingInfo.getPrivateKey());

        DigestCalculatorProvider digestCalcProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build();

        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalcProvider)
                .build(contentSigner, signingInfo.getX509Certificate());

        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
        cmsSignedDataGenerator.addCertificates(jcaCertificateHolderStore);

        CMSTypedData cmsData = new CMSProcessableByteArray(string.getBytes(StandardCharsets.UTF_8));
        return cmsSignedDataGenerator.generate(cmsData, signingInfo.isSigningAttached());
    }

    private static SigningInfo getSigningInfo(Resource pkcs12File, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(CERT_KEY_FILE_FORMAT);
        keyStore.load(pkcs12File.getInputStream(), password.toCharArray());

        String alias = keyStore.aliases().nextElement(); // Somente pega a primeira chave presente

        SigningInfo signingInfo = new SigningInfo();

        signingInfo.setPrivateKey((PrivateKey) keyStore.getKey(alias, password.toCharArray()));
        signingInfo.setX509Certificate((X509Certificate) keyStore.getCertificate(alias));

        // Gera cadeia de certificados a partir do que existe dentro da chave
        signingInfo.setCertificateHolderList(SigningService.getBCCertificateChain(keyStore.getCertificateChain(alias), signingInfo.getX509Certificate()));

        return signingInfo;
    }

    private static List<X509CertificateHolder> getBCCertificateChain(Certificate[] javaLikeCertificates, X509Certificate x509Certificate) throws CertificateEncodingException, IOException {
        List<X509CertificateHolder> bcCertificateList = new ArrayList<>();

        // Caso exista uma cadeia de certificados, adicioná-los na lista de certificados
        if (javaLikeCertificates != null && javaLikeCertificates.length != 0) {
            for (Certificate cert : javaLikeCertificates) {
                X509Certificate x509Cert = (X509Certificate) cert;
                X509CertificateHolder bcCert = new X509CertificateHolder(x509Cert.getEncoded());
                bcCertificateList.add(bcCert);
            }
            // Caso contrário, usamos somente o certificado em si.
        } else {
            X509CertificateHolder bcCert = new X509CertificateHolder(x509Certificate.getEncoded());
            bcCertificateList.add(bcCert);
        }

        return bcCertificateList;
    }
}
