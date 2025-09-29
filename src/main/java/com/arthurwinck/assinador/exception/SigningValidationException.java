package com.arthurwinck.assinador.exception;

import lombok.Getter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Map;

@Getter
public class SigningValidationException extends Exception {
    protected HttpStatus httpStatus;

    public SigningValidationException(HttpStatus status, String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = status;
    }

    public SigningValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SigningValidationException(String message) {
        super(message);
    }

    @Getter
    public enum ErrorType {
        IO_EXCEPTION("Houve um erro ao tentar instanciar o arquivo de certificados", HttpStatus.BAD_REQUEST),
        CERTIFICATE_EXCEPTION("Não foi possível carregar o arquivo de certificados", HttpStatus.BAD_REQUEST),
        ALGORITHM_KEY_EXCEPTION("Não foi possível buscar o algoritmo usado para recuperar a chave", HttpStatus.BAD_REQUEST),
        UNRECOVERABLE_KEY_EXCEPTION("Houve um erro ao tentar recuperar a chave do arquivo de certificados, a senha pode estar incorreta", HttpStatus.BAD_REQUEST),
        CMS_EXCEPTION("Não foi possível adicionar certificados para assinatura", HttpStatus.INTERNAL_SERVER_ERROR),
        OPERATOR_CREATION_EXCEPTION("Não foi possível criar estruturas para assinatura", HttpStatus.INTERNAL_SERVER_ERROR),
        CERTIFICATE_ENCODING_EXCEPTION("Não foi possível realizar o encoding do certificado para assinatura", HttpStatus.INTERNAL_SERVER_ERROR),
        KEY_STORE_EXCEPTION("Houve um erro ao tentar acessar itens do KeyStore", HttpStatus.INTERNAL_SERVER_ERROR),
        GENERIC_EXCEPTION("Houve um erro ao tentar assinar o arquivo, tente novamente", HttpStatus.INTERNAL_SERVER_ERROR);

        private final String message;
        private final HttpStatus status;

        ErrorType(String message, HttpStatus status) {
            this.message = message;
            this.status = status;
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

        return new SigningValidationException(type.getStatus(), type.getMessage(), cause);
    }
}
