package com.arthurwinck.assinador.exception;

public class InvalidSignatureFileException extends VerifyValidationException{
    public InvalidSignatureFileException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidSignatureFileException(String message) {
        super(message);
    }
}
