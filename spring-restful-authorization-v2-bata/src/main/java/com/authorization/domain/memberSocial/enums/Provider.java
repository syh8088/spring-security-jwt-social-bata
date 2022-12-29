package com.authorization.domain.memberSocial.enums;

import com.authorization.common.config.oauth2.model.response.userInfo.GoogleOAuth2UserInfo;
import com.authorization.common.config.oauth2.model.response.userInfo.KakaoOAuth2UserInfo;
import com.authorization.common.config.oauth2.model.response.userInfo.NaverOAuth2UserInfo;
import com.authorization.common.config.oauth2.model.response.userInfo.OAuth2UserInfo;
import lombok.Getter;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;

@Getter
public enum Provider {

    GOOGLE("google", GoogleOAuth2UserInfo::new),
    KAKAO("kakao", KakaoOAuth2UserInfo::new),
    NAVER("naver", NaverOAuth2UserInfo::new),
    NONE("none", attributes -> null);

    private final String provider;
    private final Function<Map<String, Object>, OAuth2UserInfo> expression;

    Provider(String provider, Function<Map<String, Object>, OAuth2UserInfo> expression) {
        this.provider = provider;
        this.expression = expression;
    }

    public String getProvider() {
        return this.provider;
    }

    public static Provider getByProvider(String provider) {
        return Arrays.stream(Provider.values())
                .filter(data -> data.getProvider().equals(provider))
                .findFirst()
                .orElse(Provider.NONE);
    }

    public OAuth2UserInfo oAuth2UserInfoCalculate(Map<String, Object> attributes) {
        return expression.apply(attributes);
    }

/*    public ClientRegistration.ClientRegistrationBuilder getBuilder(String registrationId) {
        return ClientRegistration.builder().registrationId(registrationId);
    }*/
}
