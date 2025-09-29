package com.arthurwinck.assinador.exception;

import org.springframework.http.HttpStatus;

public class InvalidCertificateException extends SigningValidationException {
    public InvalidCertificateException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidCertificateException(String message) {
        super(message);
        this.httpStatus = HttpStatus.BAD_REQUEST;
    }
}
