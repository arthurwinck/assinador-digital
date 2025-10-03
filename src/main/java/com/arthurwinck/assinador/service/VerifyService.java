package com.arthurwinck.assinador.service;

import com.arthurwinck.assinador.dto.VerifyResponse;
import com.arthurwinck.assinador.exception.InvalidSignatureFileException;
import com.arthurwinck.assinador.exception.InvalidSignedContentException;
import com.arthurwinck.assinador.exception.VerifyValidationException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.Selector;
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
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signerCertificate);
            DigestCalculatorProvider digestProvider = new BcDigestCalculatorProvider();

            // Cria DTO com todas as infos relacionadas à assinatura
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

    private static String getHexEncodedSignedContent(CMSTypedData cmsTypedData) throws InvalidSignedContentException {
        if (cmsTypedData == null) {
            throw new InvalidSignedContentException("Conteúdo não encontrado - Espera-se a assinatura e o conteúdo assinado presente no arquivo");
        }
        byte[] originalSignedData = (byte[]) cmsTypedData.getContent();
        return Hex.toHexString(originalSignedData);
    }

    private static CMSSignedData getSignedData(byte[] signedFileResource) throws InvalidSignatureFileException {
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
                throw new InvalidSignatureFileException("Não foi possível carregar arquivo de assinatura.", e);
            }
        }
        return cmsSignedData;
    }

    public static Collection<X509CertificateHolder> getCertificateMatches(CMSSignedData cmsSignedData, Selector<X509CertificateHolder> signerId) throws InvalidSignatureFileException {
        Collection<?> rawMatches = cmsSignedData.getCertificates().getMatches(signerId);
        Collection<X509CertificateHolder> matches = new ArrayList<>();

        for (Object obj : rawMatches) {
            if (obj instanceof X509CertificateHolder holder) {
                matches.add(holder);
            } else {
                throw new InvalidSignatureFileException("Tipo de objeto para certificado inesperado: " + obj.getClass());
            }
        }

        return matches;
    }

    public VerifyResponse verifySignature(CMSSignedData cmsSignedData) throws InvalidSignedContentException, InvalidSignatureFileException {
        VerifyResponse verifyResponse = new VerifyResponse();

        verifyResponse.setStatus(VerifyResponse.VerifyResponseStatusEnum.VALIDO);
        verifyResponse.setDigestAlgorithm(
                String.join(", ", this.getDigestAlgorithmStringList(cmsSignedData.getDigestAlgorithmIDs())));
        verifyResponse.setOriginalData(VerifyService.getHexEncodedSignedContent(cmsSignedData.getSignedContent()));

        // Um documento pode ser assinado por múltiplos certificados, buscar todos os certificados e suas informações
        Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();

        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> signerCollection = signers.getSigners();

        // Regra de negócio aqui, um documento nâo assinado é um documento inválido
        if (signerCollection == null || signerCollection.isEmpty()) {
            verifyResponse.setStatus(VerifyResponse.VerifyResponseStatusEnum.INVALIDO);
            return verifyResponse;
        }

        StringBuilder signerNames = new StringBuilder();
        StringBuilder encapContentInfoHashes = new StringBuilder();
        StringBuilder signingTimes = new StringBuilder();

        for (SignerInformation signer: signerCollection) {
            if (!this.verifySigner(signer, certStore)) {
                verifyResponse.setStatus(VerifyResponse.VerifyResponseStatusEnum.INVALIDO);
                return verifyResponse;
            }

            AttributeTable signedAttributes = signer.getSignedAttributes();
            if (signedAttributes != null) {
                Attribute messageDigestAttr = signedAttributes.get(CMSAttributes.messageDigest);
                if (messageDigestAttr != null) {
                    ASN1OctetString digest = (ASN1OctetString) messageDigestAttr
                            .getAttrValues()
                            .getObjectAt(0);

                    byte[] hashBytes = digest.getOctets();
                    encapContentInfoHashes.append(Hex.toHexString(hashBytes));
                }

                Attribute signingTimeAttr = signedAttributes.get(CMSAttributes.signingTime);
                if (signingTimeAttr != null) {
                    ASN1Encodable attrValue = signingTimeAttr.getAttrValues().getObjectAt(0);

                    Time time = Time.getInstance(attrValue);
                    signingTimes.append(time.getDate()) ;
                }

            }

            SignerId signerId = signer.getSID();

            Collection<X509CertificateHolder> matches = VerifyService.getCertificateMatches(cmsSignedData, signerId);

            X509CertificateHolder certHolder = matches.iterator().next();
            X500Name subject = certHolder.getSubject();
            String subjectStr = subject.toString();

            signerNames.append(subjectStr).append(",");
        }

        verifyResponse.setCNSignerName(signerNames.toString());
        verifyResponse.setEncapContentInfoHash(encapContentInfoHashes.toString());
        verifyResponse.setSigninTimeDate(signingTimes.toString());

        return verifyResponse;
    }

    public VerifyResponse verify(byte[] signedFileResource) throws VerifyValidationException {

        try {
            CMSSignedData cmsSignedData = VerifyService.getSignedData(signedFileResource);
            return this.verifySignature(cmsSignedData);
        } catch (VerifyValidationException e) {
            throw VerifyValidationException.from(e);
        }
    }
}
