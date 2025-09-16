package com.arthurwinck.assinador.service;

import com.arthurwinck.assinador.dto.SigningInfo;
import com.arthurwinck.assinador.dto.VerifyResponse;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static com.arthurwinck.assinador.service.SigningService.CERT_KEY_FILE_FORMAT;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class VerifyServiceIntegrationTest {

    @Value("${signing.key-password}")
    private String keyPassword;

    @Autowired
    private SigningService signingService;

    @Autowired
    private VerifyService verifyService;

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
    @DisplayName("Deve verificar uma assinatura válida corretamente")
    void testVerifyValidSignature() throws Exception {
        String testContent = "Documento de teste para verificação de assinatura";
        CMSSignedData signedData = signingService.sign(testContent, testSigningInfo);
        byte[] signedBytes = signedData.getEncoded();

        VerifyResponse verifyResponse = verifyService.verify(signedBytes);

        assertNotNull(verifyResponse, "VerifyResponse não pode ser nulo");
        assertEquals(VerifyResponse.VerifyResponseStatusEnum.VALIDO, verifyResponse.getStatus(),
                "Assinatura deve ser válida");

        // Deve possuir algoritmo de digest
        assertNotNull(verifyResponse.getDigestAlgorithm(), "Algoritmo de digest deve estar presente");
        assertFalse(verifyResponse.getDigestAlgorithm().trim().isEmpty(),
                "Algoritmo de digest não pode estar vazio");

        // Dados originais devem estar presentes na assinatura (ser do tipo "attached")
        assertNotNull(verifyResponse.getOriginalData(), "Dados originais devem estar presentes");
        assertFalse(verifyResponse.getOriginalData().trim().isEmpty(),
                "Dados originais não podem estar vazios");

        // Deve possuir uma representação Hex não nula
        String originalDataHex = verifyResponse.getOriginalData();
        assertNotNull(originalDataHex, "Dados originais em hex não podem ser nulos");
        assertFalse(originalDataHex.isEmpty(), "Dados originais em hex devem ter conteúdo");
    }

    @Test
    @DisplayName("Deve retornar inválido para dados corrompidos")
    void testVerifyInvalidSignature() {
        byte[] corruptedData = "dados-corrompidos-que-não-são-cms".getBytes();

        Exception exception = assertThrows(Exception.class, () -> {
            verifyService.verify(corruptedData);
        });

        assertNotNull(exception.getMessage(), "Mensagem de erro deve estar presente");
        assertTrue(exception.getMessage().contains("parsing"),
                "Mensagem deve indicar erro de parsing");
    }

    @Test
    @DisplayName("Deve processar assinatura codificada em Base64")
    void testVerifyBase64EncodedSignature() throws Exception {
        String testContent = "Documento para teste de Base64";
        CMSSignedData signedData = signingService.sign(testContent, testSigningInfo);
        byte[] signedBytes = signedData.getEncoded();

        byte[] base64EncodedSignature = org.bouncycastle.util.encoders.Base64.encode(signedBytes);

        // Deve conseguir verificar caso assinatura venha encoded em base64
        VerifyResponse verifyResponse = verifyService.verify(base64EncodedSignature);

        assertNotNull(verifyResponse, "VerifyResponse não pode ser nulo");
        assertEquals(VerifyResponse.VerifyResponseStatusEnum.VALIDO, verifyResponse.getStatus(),
                "Assinatura codificada em Base64 deve ser válida");
    }
}