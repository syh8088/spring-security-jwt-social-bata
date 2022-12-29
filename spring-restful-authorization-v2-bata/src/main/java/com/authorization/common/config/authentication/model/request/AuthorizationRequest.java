package com.authorization.common.config.authentication.model.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuthorizationRequest {

    private String username;
    private String password;

    @Builder
    public AuthorizationRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
}
