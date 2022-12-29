package com.authorization.common.config.properties;

import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secretKey;
    private String refreshKey;
    private SignatureAlgorithm signatureAlgorithm;
    private Long accessTokenExpired;
    private Long refreshTokenExpired;
}
