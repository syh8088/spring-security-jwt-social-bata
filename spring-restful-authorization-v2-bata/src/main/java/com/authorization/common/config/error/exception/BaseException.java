package com.authorization.common.config.error.exception;

import lombok.Getter;

import java.util.HashMap;

@Getter
public class BaseException extends Exception {

    private final String code;
    private final HashMap data;

    /**
     * 익셉션 코드를 리턴한다.
     *
     * @param code
     * @param message
     */
    public BaseException(String code, String message) {

        super(message);
        this.code = code;
        this.data = null;
    }
}
