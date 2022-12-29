package com.authorization.common.config.oauth2.model.request;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class OAuth2AuthorizationRequest {

    private String referer;
    private String redirectUri;
    private String callback;

    @Builder
    public OAuth2AuthorizationRequest(String referer, String redirectUri, String callback) {
        this.referer = referer;
        this.redirectUri = redirectUri;
        this.callback = callback;
    }
}
