package com.arthurwinck.assinador.resource;

import com.arthurwinck.assinador.dto.TextPayload;
import com.arthurwinck.assinador.service.HashService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/hash")
public class HashResource {

    private final HashService hashService;

    @Autowired
    public HashResource(HashService hashService) {
        this.hashService = hashService;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public String generateHash(@RequestBody TextPayload textPayload) {
        // Criar validações para payload
        return this.hashService.generateHexEncodedHash(textPayload.getText());
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public String generateHashUpload(@RequestParam MultipartFile file) throws Exception {
        String fileContent = new String(file.getBytes());
        return this.hashService.generateHexEncodedHash(fileContent);
    }
}