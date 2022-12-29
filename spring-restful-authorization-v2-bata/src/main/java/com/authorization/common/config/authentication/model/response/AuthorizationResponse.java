package com.authorization.common.config.authentication.model.response;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthorizationResponse {

    private String access_token;
    private String refresh_token;
    private Long expires_in;
    private String member_id;
    private Long member_seq;
    private Collection<? extends GrantedAuthority> authorities;

    @Builder
    public AuthorizationResponse(
            String access_token, String refresh_token, Long expires_in, String member_id, Long member_seq,
            Collection<? extends GrantedAuthority> authorities
    ) {
        this.access_token = access_token;
        this.refresh_token = refresh_token;
        this.expires_in = expires_in;
        this.member_id = member_id;
        this.member_seq = member_seq;
        this.authorities = authorities;
    }
}
