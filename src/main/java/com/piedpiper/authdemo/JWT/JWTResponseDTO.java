package com.piedpiper.authdemo.JWT;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonInclude(Include.NON_NULL)
public class JWTResponseDTO {
    private String error;
    private String token;

    public JWTResponseDTO() {}

    public JWTResponseDTO(String error, String token) {
        this.error = error;
        this.token = token;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
