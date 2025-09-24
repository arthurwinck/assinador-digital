package com.arthurwinck.assinador.exception;

public class InvalidCertificateException extends SigningValidationException {
    public InvalidCertificateException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidCertificateException(String message) {
        super(message);
    }
}
