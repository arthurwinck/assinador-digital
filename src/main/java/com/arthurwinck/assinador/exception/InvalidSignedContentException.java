package com.arthurwinck.assinador.exception;

import org.springframework.http.HttpStatus;

public class InvalidSignedContentException extends VerifyValidationException {
    public InvalidSignedContentException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidSignedContentException(String message) {
        super(message);
        this.httpStatus = HttpStatus.BAD_REQUEST;
    }
}
