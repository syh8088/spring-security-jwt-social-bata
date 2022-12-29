package com.authorization.common.enums;

public enum OauthType {
    NONE("none"),
    NAVER("naver"),
    GOOGLE("google");

    private String value;

    OauthType(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }
}
