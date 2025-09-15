package com.arthurwinck.assinador.resource;

import com.arthurwinck.assinador.dto.TextPayload;
import com.arthurwinck.assinador.service.SigningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/signature")
public class SigningResource {

    private final SigningService signingService;

    @Autowired
    public SigningResource(SigningService signingService) {
        this.signingService = signingService;
    }

    // Passar o password diretamente é ruim...
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> signUpload(@RequestParam MultipartFile file,
                                             @RequestParam MultipartFile pkcs12,
                                             @RequestHeader("X-password") String password) throws Exception {
        if (file.isEmpty() || pkcs12.isEmpty()) {
            return ResponseEntity.badRequest().body("Arquivo a ser assinado ou arquivo pkcs12 não podem ser vazios.");
        }

        String fileContent = new String(file.getBytes());

        return ResponseEntity.ok(this.signingService.signAttached(fileContent, pkcs12.getResource(), password));
    }
}
