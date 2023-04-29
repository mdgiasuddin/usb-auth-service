package com.example.authservice.dtos;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AuthenticationResponse {
    private String accessToken;
    private String refreshToken;
}
