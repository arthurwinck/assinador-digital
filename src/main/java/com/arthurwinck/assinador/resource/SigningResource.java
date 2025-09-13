package com.arthurwinck.assinador.resource;

import com.arthurwinck.assinador.dto.TextPayload;
import com.arthurwinck.assinador.service.SigningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/signing")
public class SigningResource {

    private final SigningService signingService;

    @Autowired
    public SigningResource(SigningService signingService) {
        this.signingService = signingService;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public String sign(@RequestBody TextPayload textPayload) throws Exception {
        return this.signingService.signAttached(textPayload.getText());
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public String signUpload(@RequestParam MultipartFile file) throws Exception {
        String fileContent = new String(file.getBytes());
        return this.signingService.signAttached(fileContent);
    }
}
