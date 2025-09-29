package com.arthurwinck.assinador.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.Map;

@Getter
public class VerifyValidationException extends Exception {
    protected HttpStatus httpStatus;

    public VerifyValidationException(HttpStatus httpStatus, String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = httpStatus;
    }

    public VerifyValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public VerifyValidationException(String message) {
        super(message);
    }

    @Getter
    public enum ErrorType {
        GENERIC_EXCEPTION("Houve um erro ao tentar verificar o arquivo, tente novamente", HttpStatus.INTERNAL_SERVER_ERROR),
        INVALID_CONTENT_EXCEPTION("Não foi possível carregar o conteúdo do arquivo de assinatura", HttpStatus.BAD_REQUEST),
        INVALID_FILE_EXCEPTION("Não foi possível carregar o arquivo de assinatura a ser verificado", HttpStatus.BAD_REQUEST);

        private final String message;
        private final HttpStatus status;

        ErrorType(String message, HttpStatus status) {
            this.message = message;
            this.status = status;
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

        return new VerifyValidationException(type.getStatus(), type.getMessage() + ": " + cause.getMessage(), cause);
    }
}
