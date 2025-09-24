package com.arthurwinck.assinador.exception;

import lombok.Getter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Map;

public class SigningValidationException extends Exception {

    @Getter
    public enum ErrorType {
        CMS_EXCEPTION("Não foi possível adicionar certificados para assinatura"),
        OPERATOR_CREATION_EXCEPTION("Não foi possível criar estruturas para assinatura"),
        CERTIFICATE_ENCODING_EXCEPTION("Não foi possível realizar o encoding do certificado para assinatura"),
        KEY_STORE_EXCEPTION("Houve um erro ao tentar acessar itens do KeyStore"),
        IO_EXCEPTION("Houve um erro ao tentar instanciar o arquivo de certificados"),
        CERTIFICATE_EXCEPTION("Não foi possível carregar o arquivo de certificados"),
        ALGORITHM_KEY_EXCEPTION("Não foi possível buscar o algoritmo usado para recuperar a chave"),
        UNRECOVERABLE_KEY_EXCEPTION("Houve um erro ao tentar recuperar a chave do arquivo de certificados, a senha pode estar incorreta"),
        GENERIC_EXCEPTION("Houve um erro ao tentar assinar o arquivo, tente novamente");

        private final String message;

        ErrorType(String message) {
            this.message = message;
        }

    }

    private static final Map<Class<? extends Exception>, ErrorType> ERROR_MAP = Map.of(
            CMSException.class, ErrorType.CMS_EXCEPTION,
            OperatorCreationException.class, ErrorType.OPERATOR_CREATION_EXCEPTION,
            CertificateEncodingException.class, ErrorType.CERTIFICATE_ENCODING_EXCEPTION,
            KeyStoreException.class, ErrorType.KEY_STORE_EXCEPTION,
            IOException.class, ErrorType.IO_EXCEPTION,
            NoSuchAlgorithmException.class, ErrorType.ALGORITHM_KEY_EXCEPTION,
            UnrecoverableKeyException.class, ErrorType.UNRECOVERABLE_KEY_EXCEPTION,
            CertificateException.class, ErrorType.CERTIFICATE_EXCEPTION
    );

    public static SigningValidationException from(Throwable cause) {
        ErrorType type = ERROR_MAP.getOrDefault(cause.getClass(), null);

        if (type == null) {
            type = ErrorType.GENERIC_EXCEPTION;
        }

        return new SigningValidationException(type.getMessage() + ": " + cause.getMessage(), cause);
    }

    public SigningValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SigningValidationException(String message) {
        super(message);
    }
}
