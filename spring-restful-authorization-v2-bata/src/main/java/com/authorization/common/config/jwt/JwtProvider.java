package com.authorization.common.config.jwt;


import com.authorization.common.config.properties.JwtProperties;
import com.authorization.util.DateConvertor;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;

    public String extractUsernameByAccessToken(String token) {
        return extractClaim(token, jwtProperties.getSecretKey(), Claims::getSubject);
    }

    public LocalDateTime extractExpirationByAccessToken(String token) {
        return DateConvertor.toLocalDateTime(extractClaim(token, jwtProperties.getSecretKey(), Claims::getExpiration));
    }

    private Boolean isAccessTokenExpired(String token) {
        return extractExpirationByAccessToken(token).isBefore(LocalDateTime.now());
    }

    public String extractUsernameByRefreshToken(String token) {
        return extractClaim(token, jwtProperties.getRefreshKey(), Claims::getSubject);
    }

    public LocalDateTime extractExpirationByRefreshToken(String token) {
        return DateConvertor.toLocalDateTime(extractClaim(token, jwtProperties.getRefreshKey(), Claims::getExpiration));
    }

    private Boolean isRefreshTokenExpired(String token) {
        return extractExpirationByRefreshToken(token).isBefore(LocalDateTime.now());
    }

    private <T> T extractClaim(String token, String key, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token, key);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token, String key) {
        //jwtProperties.getSecretKey()

        return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
    }

    public String generateAccessToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return generateToken(claims, username, jwtProperties.getSecretKey(), jwtProperties.getAccessTokenExpired());
    }

    public String generateRefreshToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return generateToken(claims, username, jwtProperties.getRefreshKey(), jwtProperties.getRefreshTokenExpired());
    }

    private String generateToken(Map<String, Object> claims, String subject, String key, Long expiryTime) {

        LocalDateTime expiryDate = LocalDateTime.now().plusSeconds(expiryTime);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(DateConvertor.toDate(LocalDateTime.now()))
                .setExpiration(DateConvertor.toDate(expiryDate))
                .signWith(jwtProperties.getSignatureAlgorithm(), key)
                .compact();
    }

    public boolean validateAccessToken(String token, String username) {
        final String tokenUsername = extractUsernameByAccessToken(token);
        return (username.equals(tokenUsername) && !isAccessTokenExpired(token));
    }

    public boolean validateRefreshToken(String token, String username) {
        final String tokenUsername = extractUsernameByRefreshToken(token);
        return (username.equals(tokenUsername) && !isRefreshTokenExpired(token));
    }

    public Long getAccessTokenExpirationDate() {
        return jwtProperties.getAccessTokenExpired();
    }

    public Long getRefreshTokenExpirationDate() {
        return jwtProperties.getRefreshTokenExpired();
    }
}