package com.arthurwinck.assinador.service;

import com.arthurwinck.assinador.dto.VerifyResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class VerifyService {

    private final DefaultAlgorithmNameFinder algorithmNameFinder;

    public VerifyService() {
        this.algorithmNameFinder = new DefaultAlgorithmNameFinder();
    }

    private List<String> getDigestAlgorithmStringList(Collection<AlgorithmIdentifier> algorithmIdentifierSet) {
        List<String> digestAlgorithmStringList = new ArrayList<>();

        if (algorithmIdentifierSet == null || algorithmIdentifierSet.isEmpty()) {
            return digestAlgorithmStringList;
        }

        algorithmIdentifierSet.forEach(algorithmIdentifier -> {
            String algorithmName = this.algorithmNameFinder.getAlgorithmName(algorithmIdentifier);

            if (algorithmName == null || algorithmName.trim().isEmpty()) {
                algorithmName = "Desconhecido";
            }

            digestAlgorithmStringList.add(algorithmName);
        });

        return digestAlgorithmStringList;
    }

    private boolean verifySigner(SignerInformation signerInformation, Store<X509CertificateHolder> certStore) {
        try {
            // Busca todos os certificados para posteriormente procurar pelo que está sendo verificado
            Collection<X509CertificateHolder> allCertificates = certStore.getMatches(null);

            X509CertificateHolder signerCertificate = null;

            for (X509CertificateHolder cert: allCertificates) {
                if (signerInformation.getSID().match(cert)) {
                    signerCertificate = cert;
                    break;
                }
            }

            if (signerCertificate == null) {
                return false;
            }

            CMSSignatureAlgorithmNameGenerator sigNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
            SignatureAlgorithmIdentifierFinder sigAlgorithmFinder = new DefaultSignatureAlgorithmIdentifierFinder();
            ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC")
                    .build(signerCertificate);
            DigestCalculatorProvider digestProvider = new BcDigestCalculatorProvider();

            // Create verifier with all 4 parameters
            SignerInformationVerifier verifier = new SignerInformationVerifier(
                    sigNameGenerator,
                    sigAlgorithmFinder,
                    verifierProvider,
                    digestProvider
            );

            return signerInformation.verify(verifier);

        } catch (Exception exception) {
            return false;
        }
    }

    private static String getHexEncodedSignedContent(CMSTypedData cmsTypedData) throws Exception {
        if (cmsTypedData == null) {
            throw new Exception("Conteúdo não encontrado - Espera-se a assinatura e o conteúdo assinado presente no arquivo");
        }

        byte[] originalSignedData = (byte[]) cmsTypedData.getContent();
        return Hex.toHexString(originalSignedData);
    }

    public VerifyResponse verify(byte[] signedFileResource) throws Exception {
        CMSSignedData cmsSignedData;

        try {
            // É possível realizar o parse imediatamente
            cmsSignedData = new CMSSignedData(signedFileResource);
        } catch (CMSException e) {
            // Tentar realizar o parsing após o decode de Base64
            try {
                byte[] decodedData = Base64.decode(signedFileResource);
                cmsSignedData = new CMSSignedData(decodedData);
            } catch (Exception e2) {
                throw new Exception("Nâo foi possível realizar o parsing desse arquivo: " + e.getMessage());
            }
        }

        VerifyResponse verifyResponse = new VerifyResponse();

        verifyResponse.setStatus(VerifyResponse.VerifyResponseStatusEnum.VALIDO);
        verifyResponse.setDigestAlgorithm(
                String.join(", ", this.getDigestAlgorithmStringList(cmsSignedData.getDigestAlgorithmIDs())));
        verifyResponse.setOriginalData(VerifyService.getHexEncodedSignedContent(cmsSignedData.getSignedContent()));

        // Um documento pode ser assinado por múltiplos certificados, buscar todos os certificados e suas informações
        Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();

        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signerCollection = signers.getSigners();

        // Regra de negócio aqui, mas um documento nâo assinado é um documento inválido
        if (signerCollection == null || signerCollection.isEmpty()) {
            verifyResponse.setStatus(VerifyResponse.VerifyResponseStatusEnum.INVALIDO);
            return verifyResponse;
        }

        for (SignerInformation signer: signerCollection) {
            if (!this.verifySigner(signer, certStore)) {
                verifyResponse.setStatus(VerifyResponse.VerifyResponseStatusEnum.INVALIDO);
                break;
            }
        }

        return verifyResponse;
    }
}
