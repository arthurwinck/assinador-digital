package com.arthurwinck.assinador.resource;

import com.arthurwinck.assinador.dto.VerifyResponse;
import com.arthurwinck.assinador.service.VerifyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("api/verify")
public class VerifyResource {

    private final VerifyService verifyService;

    @Autowired
    public VerifyResource(VerifyService verifyService)  { this.verifyService = verifyService; };

    @PostMapping
    public ResponseEntity<VerifyResponse> verify(@RequestParam MultipartFile fileToVerify) throws Exception {
        return ResponseEntity.ok(this.verifyService.verify(fileToVerify.getResource()));
    }
}
