package com.arthurwinck.assinador.service;

import jakarta.annotation.PostConstruct;
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
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@Component
public class SigningService {

    private final static String SIGNATURE_ALGORITHM = "SHA512withRSA";
    private final static String CERT_KEY_FILE_FORMAT = "PKCS12";

    @Value("${signing.keystore-path}")
    private Resource keystoreResource;

//    @Value("${signing.key-alias}")
//    private String signingKeyAlias;

    @Value("${signing.key-password}")
    private String signingKeyPassword;

    private PrivateKey privateKey;
    private X509Certificate x509Certificate;
    private List<X509CertificateHolder> certificateChain;


    // Aqui pesquisando, vi a informação de que é melhor ter o provider pronto na criação da classe do que somente
    // no postConstruct (posterior a instanciação) do objeto feito pelo spring
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static List<X509CertificateHolder> getBCCertificateChain(Certificate[] javaLikeCertificates, X509Certificate x509Certificate) throws CertificateEncodingException, IOException {
        List<X509CertificateHolder> bcCertificateList = new ArrayList<>();

        // Caso exista uma cadeia de certificados, adicioná-los na lista de certificados
        if (javaLikeCertificates != null) {
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

    @PostConstruct
    public void init() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(CERT_KEY_FILE_FORMAT);
        keyStore.load(keystoreResource.getInputStream(), signingKeyPassword.toCharArray());

        String alias = keyStore.aliases().nextElement();

        this.privateKey = (PrivateKey) keyStore.getKey(alias, signingKeyPassword.toCharArray());

        this.x509Certificate = (X509Certificate) keyStore.getCertificate(alias);

        // Gera cadeia de certificados a partir do que existe dentro da chave
        this.certificateChain = SigningService.getBCCertificateChain(keyStore.getCertificateChain(alias), x509Certificate);
    }

    // Documento ou conteúdo assinado deve estar anexado na estrutura da própria assinatura
    public String signAttached(String string) throws Exception {
        CMSSignedData signedString = this.sign(string, true);

        byte[] bytes = signedString.getEncoded();
        return Hex.toHexString(bytes);
    }

    // TODO - Handle exceptions later
    private CMSSignedData sign(String string, boolean isStringAttached) throws Exception {
        // Cria a estrutura que contém os certificados que serão utilizados
        Store<X509CertificateHolder> jcaCertificateHolderStore = new CollectionStore<>(this.certificateChain);
        JcaCertStoreBuilder certStore = new JcaCertStoreBuilder().addCertificates(jcaCertificateHolderStore);

        // Engine de assinatura, usando SHA512withRSA
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);

        DigestCalculatorProvider digestCalcProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build();

        SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalcProvider)
                .build(contentSigner, this.x509Certificate);

        CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
        cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
        cmsSignedDataGenerator.addCertificates(jcaCertificateHolderStore);

        CMSTypedData cmsData = new CMSProcessableByteArray(string.getBytes(StandardCharsets.UTF_8));
        return cmsSignedDataGenerator.generate(cmsData, isStringAttached);
    }
}
