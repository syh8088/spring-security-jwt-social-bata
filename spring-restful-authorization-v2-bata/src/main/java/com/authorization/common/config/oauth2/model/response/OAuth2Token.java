package com.authorization.common.config.oauth2.model.response;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class OAuth2Token {

    private String accessToken;
    private String refreshToken;
    private LocalDateTime expiredAt;

    public OAuth2Token() {
    }

    public OAuth2Token(String accessToken, String refreshToken, LocalDateTime expiredAt) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiredAt = expiredAt;
    }
}
