package com.authorization.common.config.oauth2.model.response.userInfo;

import com.authorization.domain.memberSocial.enums.Provider;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(Provider registrationId, Map<String, Object> attributes) {

        OAuth2UserInfo oAuth2UserInfo = registrationId.oAuth2UserInfoCalculate(attributes);
        if (oAuth2UserInfo == null) {
            throw new IllegalArgumentException(registrationId.getProvider().toUpperCase() + " 로그인은 지원하지 않습니다.");
        }

        return oAuth2UserInfo;

       /* if (registrationId.equalsIgnoreCase("google")) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("kakao")) {
            return new KakaoOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase("naver")) {
            return new NaverOAuth2UserInfo(attributes);
        } else {
            throw new IllegalArgumentException(registrationId.toUpperCase() + " 로그인은 지원하지 않습니다.");
        }*/
    }
}