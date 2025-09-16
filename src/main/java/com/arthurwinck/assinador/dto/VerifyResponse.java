package com.arthurwinck.assinador.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class VerifyResponse {

    @Getter
    public enum VerifyResponseStatusEnum {
        VALIDO("Válido"),
        INVALIDO("Inválido");

        private final String literal;

        VerifyResponseStatusEnum(String literal) {
            this.literal = literal;
        }
    }

    private String originalData;
    private VerifyResponseStatusEnum status;
    private String CNSignerName;
    private String signinTimeDate;
    private String encapContentInfoHash;
    private String digestAlgorithm;
}
