package com.arthurwinck.assinador.service;

import com.arthurwinck.assinador.dto.SigningInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import static com.arthurwinck.assinador.service.SigningService.CERT_KEY_FILE_FORMAT;
import static com.arthurwinck.assinador.service.SigningService.SIGNATURE_ALGORITHM;
import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@SpringBootTest
class SigningServiceIntegrationTest {

    @Value("${signing.key-password}")
    private String keyPassword;

    @InjectMocks
    private SigningService signingService;

    private PrivateKey testPrivateKey;
    private java.security.cert.X509Certificate testJavaCertificate;
    private SigningInfo testSigningInfo;

    @BeforeAll
    static void setUpBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        loadTestCertificate();
        setupSigningInfo();
    }

    private void loadTestCertificate() throws Exception {
        ClassPathResource keystoreResource = new ClassPathResource("/keys/certificado_teste_hub.pfx");

        if (!keystoreResource.exists()) {
            fail("Certificado não encontrado. Por favor adicione o certificado com nome de certificado_teste_hub.pfx em src/test/resources/keys com a senha dentro da variável de ambiente KEY_PASSWORD");
        }

        try (InputStream keystoreStream = keystoreResource.getInputStream()) {
            KeyStore keyStore = KeyStore.getInstance(CERT_KEY_FILE_FORMAT);
            char[] password = keyPassword.toCharArray();
            keyStore.load(keystoreStream, password);
            String alias = keyStore.aliases().nextElement();
            testPrivateKey = (PrivateKey) keyStore.getKey(alias, password);

            // Busca o certificado para depois adicioná-lo na lista
            testJavaCertificate = (java.security.cert.X509Certificate) keyStore.getCertificate(alias);
        }
    }

    private void setupSigningInfo() throws Exception {
        testSigningInfo = new SigningInfo();
        testSigningInfo.setPrivateKey(testPrivateKey);
        testSigningInfo.setX509Certificate(testJavaCertificate);
        testSigningInfo.setSigningAttached(true);

        List<X509CertificateHolder> certificateHolderList = new ArrayList<>();
        X509CertificateHolder bcCert = new X509CertificateHolder(testJavaCertificate.getEncoded());
        certificateHolderList.add(bcCert);

        testSigningInfo.setCertificateHolderList(certificateHolderList);
    }

    @Test
    @DisplayName("Deve criar assinatura do tipo CMS corretamente com certificado real")
    void testSigningWithRealCertificate() throws Exception {
        String testContent = "Teste de documento para assinatura";

        CMSSignedData signedData = signingService.sign(testContent, testSigningInfo);

        assertNotNull(signedData, "Assinatura não pode ser nula");
        assertNotNull(signedData.getEncoded(), "dados codificados não podem ser nulos");
        assertTrue(signedData.getEncoded().length > 0, "dados codificados não podem ser vazios");

        CMSTypedData signedContent = signedData.getSignedContent();
        assertNotNull(signedContent, "Assinatura 'attached' precisa ter o conteúdo presente");

        byte[] originalData = (byte[]) signedContent.getContent();
        assertNotNull(originalData, "Dados originais não podem ser vazios");
        assertEquals(testContent, new String(originalData), "Conteúdo original precisa ser igual ao valor do input");

        SignerInformationStore signerInfos = signedData.getSignerInfos();
        assertNotNull(signerInfos, "Deve ter as informações do assinante");
        assertEquals(1, signerInfos.size(), "Deve possuir somente um assinante");

        SignerInformation signerInfo = signerInfos.getSigners().iterator().next();
        assertNotNull(signerInfo, "Deve possuir a informação de assinatura");
        assertNotNull(signerInfo.getSignature(), "Assinatura deve estar presente");
        assertTrue(signerInfo.getSignature().length > 0, "Assinatura não pode ser vazia");

        assertNotNull(signedData.getCertificates(), "Deve possuir certificate store");
        Collection<X509CertificateHolder> certificates = signedData.getCertificates().getMatches(null);
        assertFalse(certificates.isEmpty(), "Deve possuir pelo menos um certificado");
        assertEquals(1, certificates.size(), "Deve possuir exatamente um certificado para esse teste");

        X509CertificateHolder includedCert = certificates.iterator().next();
        assertNotNull(includedCert, "Certificate holder não pode ser nulo");

        // Valida se os dois certificados, o incluído e o reconstruído são iguais
        byte[] originalCertEncoded = testJavaCertificate.getEncoded();
        byte[] includedCertEncoded = includedCert.getEncoded();
        assertArrayEquals(originalCertEncoded, includedCertEncoded,
                "Certificado incluído é igual ao certificado encontrado");

        // Valida o algoritmo utilizado para a criptografia (SHA512WithRSA)
        String encryptionAlgOID = signerInfo.getEncryptionAlgOID();
        ASN1ObjectIdentifier algorithmOID = new ASN1ObjectIdentifier(encryptionAlgOID);

        DefaultAlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();

        assertTrue(algorithmNameFinder.getAlgorithmName(algorithmOID).equals(SIGNATURE_ALGORITHM),
                " got: " + encryptionAlgOID);

        // Verificar que é possível reconstruir dados a partir do conteúdo presente na assinatura
        byte[] encodedSignature = signedData.getEncoded();
        CMSSignedData reconstructedSignedData = new CMSSignedData(encodedSignature);

        assertNotNull(reconstructedSignedData, "Deve ser possível reconstruir conteúdo a partir dos bytes presentes na assinatura");

        CMSTypedData reconstructedContent = reconstructedSignedData.getSignedContent();
        assertNotNull(reconstructedContent, "Conteúdo não pode ser nulo");

        String reconstructedContentString = new String((byte[]) reconstructedContent.getContent());
        assertEquals(testContent, reconstructedContentString, "Conteúdo reconstruído deve ser igual ao conteúdo original");

        // Validando que existe dono do certificado e podemos buscar o seu nome
        String subjectDN = includedCert.getSubject().toString();
        assertNotNull(subjectDN, "Certificate subject should not be null");
        assertFalse(subjectDN.trim().isEmpty(), "Certificate subject should not be empty");
    }
}