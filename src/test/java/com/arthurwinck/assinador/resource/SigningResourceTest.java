package com.arthurwinck.assinador.resource;

import com.arthurwinck.assinador.exception.InvalidCertificateException;
import com.arthurwinck.assinador.exception.InvalidSignatureFileException;
import com.arthurwinck.assinador.exception.SigningValidationException;
import com.arthurwinck.assinador.service.SigningService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(SigningResource.class)
public class SigningResourceTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SigningService signingService;

    @Test
    @DisplayName("/signature must return exception thrown in service")
    void signatureResourceReturnsExceptionFromService() throws Exception {
        String errorMessage = "Não foi possível carregar o arquivo de certificados.";
        byte[] bytesArquivoAssinatura = "arquivo de certificado inválido".getBytes();
        byte[] bytesArquivoParaAssinar = "arquivo para assinar".getBytes();

        when(signingService.signAttached(any(), any(), any())).thenThrow(new InvalidCertificateException(errorMessage));

        this.mockMvc.perform(multipart("/signature")
                        .file(new MockMultipartFile("file", bytesArquivoParaAssinar))
                        .file(new MockMultipartFile("pkcs12", bytesArquivoAssinatura))
                        .header("X-password", "Senha para arquivo de assinatura"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(errorMessage));
    }

    @Test
    @DisplayName("/signature must return a string containing the signature")
    void signatureResourceReturnsSignatureFromService() throws Exception {
        byte[] bytesArquivoAssinatura = "arquivo de certificado válido".getBytes();
        byte[] bytesArquivoParaAssinar = "arquivo para assinar".getBytes();

        String hexCodedSignature = "Assinatura codificada em hex";
        when(signingService.signAttached(any(), any(), any())).thenReturn(hexCodedSignature);

        this.mockMvc.perform(multipart("/signature")
                        .file(new MockMultipartFile("file", bytesArquivoParaAssinar))
                        .file(new MockMultipartFile("pkcs12", bytesArquivoAssinatura))
                        .header("X-password", "Senha para arquivo de assinatura"))
                .andExpect(status().is2xxSuccessful())
                .andExpect(content().string(hexCodedSignature));
    }
}
