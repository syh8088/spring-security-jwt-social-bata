package com.authorization.common.config.error.model;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class CommonErrorResponse {

    private String errorCode;
    private String message;
    private int status;

    @Builder
    public CommonErrorResponse(String errorCode, String message, int status) {
        this.errorCode = errorCode;
        this.message = message;
        this.status = status;
    }
}
