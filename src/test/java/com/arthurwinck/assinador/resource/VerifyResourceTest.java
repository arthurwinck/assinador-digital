package com.arthurwinck.assinador.resource;

import com.arthurwinck.assinador.dto.VerifyResponse;
import com.arthurwinck.assinador.exception.InvalidSignatureFileException;
import com.arthurwinck.assinador.service.VerifyService;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;

import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(VerifyResource.class)
public class VerifyResourceTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private VerifyService verifyService;

    @Test
    @DisplayName("/verify must return exception thrown in service")
    void verifyResourceReturnsExceptionFromService() throws Exception {
        String errorMessage = "Não foi possível carregar arquivo de assinatura.";
        byte[] bytesArquivoAssinatura = "conteúdo inválido".getBytes();

        when(verifyService.verify(any())).thenThrow(new InvalidSignatureFileException("Não foi possível carregar arquivo de assinatura."));

        this.mockMvc.perform(multipart("/verify").file(new MockMultipartFile("file", bytesArquivoAssinatura)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(errorMessage));
    }

    @Test
    @DisplayName("/verify must correctly return information about signature")
    void verifyResourceReturnsVerifyInfo() throws Exception {
        VerifyResponse verifyResponse = VerifyResourceTest.getValidResponseDTO();
        byte[] bytesArquivoAssinatura = "conteúdo válido".getBytes();

        when(verifyService.verify(any())).thenReturn(verifyResponse);

        this.mockMvc.perform(multipart("/verify").file(new MockMultipartFile("file", bytesArquivoAssinatura)))
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.error").isEmpty())
                .andExpect(jsonPath("$.originalData").value(verifyResponse.getOriginalData()))
                .andExpect(jsonPath("$.cnsignerName").value(verifyResponse.getCNSignerName()))
                .andExpect(jsonPath("$.signinTimeDate").value(verifyResponse.getSigninTimeDate()))
                .andExpect(jsonPath("$.encapContentInfoHash").value(verifyResponse.getEncapContentInfoHash()))
                .andExpect(jsonPath("$.digestAlgorithm").value(verifyResponse.getDigestAlgorithm()));
    }

    public static VerifyResponse getValidResponseDTO() {
        VerifyResponse verifyResponse = new VerifyResponse();
        verifyResponse.setStatus(VerifyResponse.VerifyResponseStatusEnum.VALIDO);
        verifyResponse.setOriginalData("Conteúdo assinado");
        verifyResponse.setDigestAlgorithm("SHA512");
        verifyResponse.setCNSignerName("Autor da assinatura e outras informações");
        verifyResponse.setEncapContentInfoHash("Algum valor hash");
        verifyResponse.setSigninTimeDate("20251001");

        return verifyResponse;
    }
}
