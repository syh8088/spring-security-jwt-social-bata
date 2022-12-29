package com.authorization.common.config;

import com.authorization.common.config.properties.OAuth2ClientProperties;
import com.authorization.common.config.oauth2.model.ClientRegistration;
import com.authorization.common.config.oauth2.repository.ClientRegistrationRepository;
import com.authorization.domain.memberSocial.enums.Provider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class OAuth2Config {

    private final OAuth2ClientProperties oAuth2ClientProperties;

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {

        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(this::getRegistration)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        return new ClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration(String client) {

        Provider provider = Provider.getByProvider(client);
        ClientRegistration clientRegistration = ClientRegistration.builder()
                .registrationId(provider)
                .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                .authorizationGrantType(oAuth2ClientProperties.getRegistration().get(client).getAuthorizationGrantType())
                .redirectUri(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                .scopes(oAuth2ClientProperties.getRegistration().get(client).getScope())
                .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                .unlinkUri(oAuth2ClientProperties.getProvider().get(client).getUnlinkUri())
                .build();

        System.out.println("clientRegistration = " + clientRegistration);

        return clientRegistration;
/*
        if (client.equals("google")) {
            return Provider.GOOGLE.getBuilder(client)
                    .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                    .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                    .authorizationGrantType(oAuth2ClientProperties.getRegistration().get(client).getAuthorizationGrantType())
                    .redirectUri(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                    .scopes(oAuth2ClientProperties.getRegistration().get(client).getScope())
                    .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                    .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                    .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                    .unlinkUri(oAuth2ClientProperties.getProvider().get(client).getUnlinkUri())
                    .build();
        }
        if (client.equals("naver")) {
            return Provider.NAVER.getBuilder(client)
                    .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                    .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                    .authorizationGrantType(oAuth2ClientProperties.getRegistration().get(client).getAuthorizationGrantType())
                    .redirectUri(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                    .scopes(oAuth2ClientProperties.getRegistration().get(client).getScope())
                    .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                    .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                    .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                    .unlinkUri(oAuth2ClientProperties.getProvider().get(client).getUnlinkUri())
                    .build();
        }
        if (client.equals("kakao")) {
            return Provider.KAKAO.getBuilder(client)
                    .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                    .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                    .authorizationGrantType(oAuth2ClientProperties.getRegistration().get(client).getAuthorizationGrantType())
                    .redirectUri(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                    .scopes(oAuth2ClientProperties.getRegistration().get(client).getScope())
                    .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                    .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                    .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                    .unlinkUri(oAuth2ClientProperties.getProvider().get(client).getUnlinkUri())
                    .build();
        }*/
        //return null;
    }
}
