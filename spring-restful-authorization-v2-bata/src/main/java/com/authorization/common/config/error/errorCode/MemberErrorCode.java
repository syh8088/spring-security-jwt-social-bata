package com.authorization.common.config.error.errorCode;

public enum MemberErrorCode implements ErrorCode {

    NOT_EXIST_USERNAME_OR_PASSWORD("MEC0001"),
    AUTHENTICATION_FAILED("MEC0002"),
    INVALID_TOKEN("MEC0003"),
    NOT_FOUND_USERNAME("MEC0004");

    private final String code;

    MemberErrorCode(String code) {
        this.code = code;
    }

    @Override
    public String getCode() {
        return "error.member." + code;
    }
}
