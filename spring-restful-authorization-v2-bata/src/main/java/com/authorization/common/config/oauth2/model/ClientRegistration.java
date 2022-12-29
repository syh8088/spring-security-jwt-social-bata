package com.authorization.common.config.oauth2.model;

import com.authorization.domain.memberSocial.enums.Provider;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Collections;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
public final class ClientRegistration {

    private Provider registrationId;
    private String clientId;
    private String clientSecret;
    private String authorizationGrantType;
    private String redirectUri;
    private Set<String> scopes = Collections.emptySet();
    private ProviderDetails providerDetails = new ProviderDetails();

    @Builder
    public ClientRegistration(
            Provider registrationId, String clientId,
            String authorizationGrantType, String clientSecret,
            String redirectUri, Set<String> scopes,
            String authorizationUri, String tokenUri,
            String userInfoUri, String unlinkUri
    ) {

        this.registrationId = registrationId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authorizationGrantType = authorizationGrantType;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.providerDetails.authorizationUri = authorizationUri;
        this.providerDetails.tokenUri = tokenUri;
        this.providerDetails.userInfoUri = userInfoUri;
        this.providerDetails.unlinkUri = unlinkUri;
    }

    @Getter
    @Setter
    public class ProviderDetails {
        private String authorizationUri;
        private String tokenUri;
        private String userInfoUri;
        private String unlinkUri;
    }
}