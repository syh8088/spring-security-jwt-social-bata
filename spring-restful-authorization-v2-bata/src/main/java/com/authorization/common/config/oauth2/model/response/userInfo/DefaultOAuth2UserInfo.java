package com.authorization.common.config.oauth2.model.response.userInfo;

import java.util.Map;

public class DefaultOAuth2UserInfo  extends OAuth2UserInfo {

    public DefaultOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }
}

