package com.authorization.common.config.error.exception;

import com.authorization.common.config.error.errorCode.ErrorCode;
import com.authorization.common.config.handler.CustomMessageHandler;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class CommonException extends RuntimeException {
    private ErrorCode errorCode;
    private String message;
    private int status;

    public CommonException(ErrorCode errorCode) {
        super(errorCode.getCode());
        this.errorCode = errorCode;
        this.message = CustomMessageHandler.getMessage(errorCode.getCode());
    }

    public CommonException(ErrorCode errorCode, Object[] errorMessages) {
        super(errorCode.getCode());
        this.errorCode = errorCode;
        this.message = CustomMessageHandler.getMessage(errorCode.getCode(), errorMessages);
    }

    @Override
    public String getMessage() {
        return message;
    }

    public String getErrorCode() {
        return errorCode.getCode();
    }
}
