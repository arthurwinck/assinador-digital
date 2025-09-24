package com.arthurwinck.assinador.exception;

import lombok.Getter;
import java.util.Map;

public class VerifyValidationException extends Exception {
    public VerifyValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public VerifyValidationException(String message) {
        super(message);
    }

    @Getter
    public enum ErrorType {
        GENERIC_EXCEPTION("Houve um erro ao tentar verificar o arquivo, tente novamente"),
        INVALID_CONTENT_EXCEPTION("Não foi possível carregar o conteúdo do arquivo de assinatura"),
        INVALID_FILE_EXCEPTION("Não foi possível carregar o arquivo de assinatura a ser verificado");

        private final String message;

        ErrorType(String message) {
            this.message = message;
        }

    }

    private static final Map<Class<? extends Exception>, VerifyValidationException.ErrorType> ERROR_MAP = Map.of(
            InvalidSignedContentException.class, ErrorType.INVALID_CONTENT_EXCEPTION,
            InvalidSignatureFileException.class, ErrorType.INVALID_FILE_EXCEPTION,
            IllegalArgumentException.class, ErrorType.GENERIC_EXCEPTION
    );

    public static VerifyValidationException from(Throwable cause) {
        VerifyValidationException.ErrorType type = ERROR_MAP.getOrDefault(cause.getClass(), null);

        if (type == null) {
            type = VerifyValidationException.ErrorType.GENERIC_EXCEPTION;
        }

        return new VerifyValidationException(type.getMessage() + ": " + cause.getMessage(), cause);
    }
}
