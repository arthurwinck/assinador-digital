package com.arthurwinck.assinador.exception;

public class InvalidSignedContentException extends VerifyValidationException {
    public InvalidSignedContentException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidSignedContentException(String message) {
        super(message);
    }
}
