package com.arthurwinck.assinador.exception;

import org.springframework.http.HttpStatus;

public class InvalidSignatureFileException extends VerifyValidationException{
    public InvalidSignatureFileException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidSignatureFileException(String message) {
        super(message);
        this.httpStatus = HttpStatus.BAD_REQUEST;
    }
}
