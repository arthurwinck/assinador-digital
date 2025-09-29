package com.arthurwinck.assinador.resource;

import com.arthurwinck.assinador.dto.VerifyResponse;
import com.arthurwinck.assinador.exception.VerifyValidationException;
import com.arthurwinck.assinador.service.VerifyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

import static com.arthurwinck.assinador.exception.VerifyValidationException.ErrorType.INVALID_FILE_EXCEPTION;

@RestController
@RequestMapping("/verify")
public class VerifyResource {

    private final VerifyService verifyService;

    @Autowired
    public VerifyResource(VerifyService verifyService)  { this.verifyService = verifyService; };

    @PostMapping
    public ResponseEntity<VerifyResponse> verify(@RequestParam MultipartFile file) {
        try {
            return ResponseEntity.ok(this.verifyService.verify(file.getBytes()));
        } catch (VerifyValidationException | IOException e) {
            VerifyResponse response = new VerifyResponse();

            String errorMessage = (e instanceof VerifyValidationException) ? e.getMessage() : INVALID_FILE_EXCEPTION.getMessage();
            response.setError(errorMessage);

            HttpStatus status = (e instanceof VerifyValidationException)
                    ? ((VerifyValidationException) e).getHttpStatus()
                    : HttpStatus.BAD_REQUEST;

            return ResponseEntity.status(status).body(response);
        }
    }
}
